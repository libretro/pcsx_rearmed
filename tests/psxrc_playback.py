"""Compare desktop libretro playback of one original disc and its PSXRC round trips."""

import argparse
from collections import Counter
import ctypes as c
import hashlib
import os
from pathlib import Path
from time import perf_counter


class Game(c.Structure):
    _fields_ = [("path", c.c_char_p), ("data", c.c_void_p),
                ("size", c.c_size_t), ("meta", c.c_char_p)]


class Variable(c.Structure):
    _fields_ = [("key", c.c_char_p), ("value", c.c_char_p)]


ENVIRONMENT = c.CFUNCTYPE(c.c_bool, c.c_uint, c.c_void_p)
VIDEO = c.CFUNCTYPE(None, c.c_void_p, c.c_uint, c.c_uint, c.c_size_t)
AUDIO = c.CFUNCTYPE(None, c.c_int16, c.c_int16)
AUDIO_BATCH = c.CFUNCTYPE(c.c_size_t, c.c_void_p, c.c_size_t)
LOG = c.CFUNCTYPE(None, c.c_int, c.c_char_p, c.c_void_p)
POLL = c.CFUNCTYPE(None)
INPUT = c.CFUNCTYPE(c.c_int16, c.c_uint, c.c_uint, c.c_uint, c.c_uint)


class DiskControl(c.Structure):
    _fields_ = [
        ("set_ejected", c.CFUNCTYPE(c.c_bool, c.c_bool)),
        ("get_ejected", c.CFUNCTYPE(c.c_bool)),
        ("get_index", c.CFUNCTYPE(c.c_uint)),
        ("set_index", c.CFUNCTYPE(c.c_bool, c.c_uint)),
        ("count", c.CFUNCTYPE(c.c_uint)),
    ]


def playback(library, image, frame_count, readahead, system, bios, capture=None, taps=(),
             reload_state=False, swap_at=None, snapshot=None, startup=None, checkpoints=(),
             direct_xa=False, log_messages=None, audio_stats=None, direct_h264=False):
    core = c.CDLL(str(library))
    core.retro_load_game.argtypes = [c.POINTER(Game)]
    core.retro_load_game.restype = c.c_bool
    system_path = c.create_string_buffer(os.fsencode(system))
    core_path = c.create_string_buffer(os.fsencode(library))
    options = {
        b"pcsx_rearmed_bios": c.create_string_buffer(bios.encode()),
        b"pcsx_rearmed_cd_readahead": c.create_string_buffer(str(readahead).encode()),
        b"pcsx_rearmed_drc": c.create_string_buffer(b"disabled"),
        b"pcsx_rearmed_gpu_thread_rendering": c.create_string_buffer(b"disabled"),
        b"pcsx_rearmed_psxrc_direct_audio": c.create_string_buffer(b"enabled" if direct_xa else b"disabled"),
        b"pcsx_rearmed_psxrc_direct_h264": c.create_string_buffer(b"enabled" if direct_h264 else b"disabled"),
    }
    frames = set()
    geometry = Counter()
    max_diversity = 0
    last_pixels = None
    frame_number = 0
    state = None
    disk = None

    if reload_state:
        core.retro_serialize_size.restype = c.c_size_t
        core.retro_serialize.argtypes = [c.c_void_p, c.c_size_t]
        core.retro_serialize.restype = c.c_bool
        core.retro_unserialize.argtypes = [c.c_void_p, c.c_size_t]
        core.retro_unserialize.restype = c.c_bool

    @LOG
    def log(_level, fmt, message):
        if fmt == b"%s" and message:
            log_messages.append(c.string_at(message))

    @ENVIRONMENT
    def environment(command, data):
        nonlocal disk
        if command in (9, 19, 31):
            c.cast(data, c.POINTER(c.c_void_p))[0] = c.addressof(core_path if command == 19 else system_path)
            return True
        if command == 15:
            var = c.cast(data, c.POINTER(Variable))
            value = options.get(var.contents.key)
            if value is not None:
                var.contents.value = c.cast(value, c.c_char_p)
                return True
            return False
        if command == 13:
            disk = DiskControl.from_buffer_copy(c.string_at(data, c.sizeof(DiskControl)))
            return True
        if command == 27 and log_messages is not None:
            c.cast(data, c.POINTER(LOG))[0] = log
            return True
        if command in (3, 17):
            c.cast(data, c.POINTER(c.c_bool))[0] = command == 3
            return True
        if command in (39, 52):
            c.cast(data, c.POINTER(c.c_uint))[0] = 0
            return True
        return command in (10, 18, 37)

    @VIDEO
    def video(data, width, height, pitch):
        nonlocal max_diversity, last_pixels
        geometry[(width, height, bool(data))] += 1
        if not data or width < 240 or height < 180:
            return
        if capture or snapshot is not None or startup is not None:
            last_pixels = (width, height, b"".join(c.string_at(data + y * pitch, width * 2)
                                                   for y in range(height)))
        # Sample the center of the movie, away from the SDK example's status overlay.
        lines = [c.string_at(data + y * pitch + 48 * 2, 192 * 2)
                 for y in range(48, 176, 4)]
        pixels = b"".join(lines)
        diversity = len(set(pixels))
        max_diversity = max(diversity, max_diversity)
        if diversity > 48:
            frames.add(hashlib.sha256(pixels).digest())

    @AUDIO_BATCH
    def audio_batch(data, count):
        if audio_stats is not None:
            audio_stats["frames"] += count
            audio_stats["audible_batches"] += bool(c.string_at(data, count * 4).strip(b"\x00"))
        return count

    callbacks = {
        "environment": environment,
        "video_refresh": video,
        "audio_sample": AUDIO(lambda left, right: None),
        "audio_sample_batch": audio_batch,
        "input_poll": POLL(lambda: None),
        "input_state": INPUT(lambda port, device, index, button: int(port == 0 and any(
            key == button and at <= frame_number < at + 4 for at, key in taps))),
    }
    for name, callback in callbacks.items():
        setter = getattr(core, f"retro_set_{name}")
        setter.argtypes = [type(callback)]
        setter(callback)
    core.retro_init()
    try:
        load_started = perf_counter()
        if not core.retro_load_game(c.byref(Game(os.fsencode(image), None, 0, None))):
            raise RuntimeError(f"Could not boot {image}")
        if startup is not None:
            startup["load_ms"] = (perf_counter() - load_started) * 1000
            startup["checkpoints"] = {}
        try:
            for frame_number in range(frame_count):
                core.retro_run()
                if startup is not None and frame_number in checkpoints:
                    startup["checkpoints"][frame_number] = ((perf_counter() - load_started) * 1000, last_pixels)
                if reload_state and frame_number == frame_count // 2:
                    state = c.create_string_buffer(core.retro_serialize_size())
                    if not core.retro_serialize(state, len(state)):
                        raise RuntimeError(f"Could not save a state for {image}")
                elif state is not None and frame_number == frame_count // 2 + 30:
                    if not core.retro_unserialize(state, len(state)):
                        raise RuntimeError(f"Could not restore a state for {image}")
                if frame_number == swap_at:
                    if not disk or disk.count() < 2 or not disk.set_ejected(True) or \
                            not disk.set_index(1) or not disk.set_ejected(False) or disk.get_index() != 1:
                        raise RuntimeError(f"Could not switch to disc 2 for {image}")
        finally:
            core.retro_unload_game()
    finally:
        core.retro_deinit()
    if not frames:
        print(f"{image.name}: video callbacks {dict(geometry)}, byte diversity {max_diversity}", flush=True)
    if snapshot is not None:
        snapshot.append(last_pixels)
    if capture and last_pixels:
        write_png(capture, last_pixels)
    return frames


def write_png(path, pixels):
    import struct
    import zlib

    width, height, data = pixels
    rows = []
    for y in range(height):
        row = bytearray([0])
        for (value,) in struct.iter_unpack("<H", data[y * width * 2:(y + 1) * width * 2]):
            row.extend(((value >> 11) * 255 // 31, ((value >> 5) & 63) * 255 // 63,
                        (value & 31) * 255 // 31))
        rows.append(row)

    def chunk(kind, content):
        return struct.pack(">I", len(content)) + kind + content + struct.pack(">I", zlib.crc32(kind + content))

    path.write_bytes(b"\x89PNG\r\n\x1a\n" +
                     chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) +
                     chunk(b"IDAT", zlib.compress(b"".join(rows))) + chunk(b"IEND", b""))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path)
    parser.add_argument("original", type=Path)
    parser.add_argument("lossless", type=Path)
    parser.add_argument("rebuilt", type=Path)
    parser.add_argument("compressed", type=Path)
    parser.add_argument("--system", type=Path, required=True)
    parser.add_argument("--stock", type=Path, help="Optional upstream libretro build")
    parser.add_argument("--dll-directory", type=Path, action="append", default=[])
    parser.add_argument("--frames", type=int, default=540)
    parser.add_argument("--bios", choices=("Auto", "HLE"), default="Auto")
    parser.add_argument("--capture", type=Path, help="Write the original disc's last RGB565 frame as a PNG")
    parser.add_argument("--playlist", type=Path, help="An M3U with the original and converted movie disc")
    args = parser.parse_args()
    directories = [os.add_dll_directory(str(directory.resolve())) for directory in args.dll_directory]
    try:
        for readahead in (0, 12):
            library = args.library.resolve()
            stock = args.stock.resolve() if args.stock else library
            system = args.system.resolve()
            original = playback(stock, args.original.resolve(), args.frames, readahead, system, args.bios, args.capture)
            lossless = playback(library, args.lossless.resolve(), args.frames, readahead, system, args.bios)
            rebuilt = playback(stock, args.rebuilt.resolve(), args.frames, readahead, system, args.bios)
            compressed = playback(library, args.compressed.resolve(), args.frames, readahead, system, args.bios)
            print(f"read-ahead {readahead}: {len(original)}/{len(lossless)}/{len(rebuilt)}/{len(compressed)} movie frames",
                  flush=True)
            if min(len(original), len(rebuilt)) < 6 or original != lossless or rebuilt != compressed:
                raise AssertionError("Playback frame sets differ or the fixture produced too few movie frames")
            if args.playlist:
                frames = playback(library, args.playlist.resolve(), args.frames, readahead, system,
                                  args.bios, swap_at=args.frames // 2)
                if len(frames) < 6:
                    raise AssertionError("Playlist playback produced too few movie frames")
                print("Switched from BIN/CUE to PSXRC via the libretro disk control API.", flush=True)
    finally:
        for directory in directories:
            directory.close()


if __name__ == "__main__":
    main()

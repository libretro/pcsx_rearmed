"""Boot the source and converted disc, replay inputs, and reload an in-memory save state."""

import argparse
import os
from pathlib import Path
import struct

from psxrc_playback import playback


def parse_tap(value):
    try:
        frame, button = map(int, value.split(":"))
        if frame < 0 or not 0 <= button <= 15:
            raise ValueError
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected FRAME:LIBRETRO_BUTTON with button from 0 to 15") from error
    return frame, button


def raster_difference(source, converted):
    if source is None or converted is None or source[:2] != converted[:2]:
        return None
    before = struct.iter_unpack("<H", source[2])
    after = struct.iter_unpack("<H", converted[2])
    total = 0.0
    for (a,), (b,) in zip(before, after, strict=True):
        total += abs((a >> 11) - (b >> 11)) * (255 / 31)
        total += abs(((a >> 5) & 63) - ((b >> 5) & 63)) * (255 / 63)
        total += abs((a & 31) - (b & 31)) * (255 / 31)
    return total / (source[0] * source[1] * 3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stock", type=Path)
    parser.add_argument("fork", type=Path)
    parser.add_argument("source", type=Path)
    parser.add_argument("psxrc", type=Path)
    parser.add_argument("--system", type=Path, required=True)
    parser.add_argument("--dll-directory", type=Path, action="append", default=[])
    parser.add_argument("--bios", choices=("Auto", "HLE"), default="Auto")
    parser.add_argument("--frames", type=int, default=1650)
    parser.add_argument("--direct-xa", action="store_true", help="Enable and require direct Opus XA playback")
    parser.add_argument("--direct-h264", action="store_true", help="Enable and require direct H.264 video output")
    parser.add_argument("--readahead", type=int, choices=(0, 12), default=12)
    parser.add_argument("--tap", type=parse_tap, action="append", default=[])
    parser.add_argument("--capture-dir", type=Path)
    args = parser.parse_args()
    directories = [os.add_dll_directory(str(directory.resolve())) for directory in args.dll_directory]
    try:
        frames = []
        rasters = []
        messages = []
        audio_stats = []
        for label, core, image in (("source", args.stock, args.source), ("psxrc", args.fork, args.psxrc)):
            capture = None
            if args.capture_dir:
                args.capture_dir.mkdir(exist_ok=True)
                capture = args.capture_dir / f"{label}.png"
            audio_stats.append({"frames": 0, "audible_batches": 0})
            frames.append(playback(core.resolve(), image.resolve(), args.frames, args.readahead,
                                   args.system.resolve(), args.bios, capture, args.tap, reload_state=True,
                                   snapshot=rasters, direct_xa=args.direct_xa and label == "psxrc",
                                   log_messages=messages if (args.direct_xa or args.direct_h264) and label == "psxrc" else None,
                                   audio_stats=audio_stats[-1] if args.direct_xa else None,
                                   direct_h264=args.direct_h264 and label == "psxrc"))
        if args.direct_h264:
            if b"PSXRC: playing H.264 video directly through MDEC\n" not in messages:
                raise SystemExit("No direct H.264 output was observed")
            print("Direct H.264 video output observed.")
        if args.direct_xa:
            if b"PSXRC: playing Opus XA audio directly\n" not in messages:
                raise SystemExit("No direct XA playback was observed")
            if min(stats["audible_batches"] for stats in audio_stats) == 0:
                raise SystemExit("One of the XA runs produced silent audio")
            print(f"Direct XA playback observed. Audio frames delivered: "
                  f"{audio_stats[0]['frames']} source, {audio_stats[1]['frames']} PSXRC.")
        shared = len(frames[0] & frames[1])
        delta = raster_difference(*rasters)
        print(f"Ran {args.frames} frames and saved and reloaded each game. "
              f"{len(frames[0])} source samples, {len(frames[1])} PSXRC samples, {shared} exact matches.")
        if delta is not None:
            print(f"Final frame mean channel difference {delta:.2f}/255.")
        if min(map(len, frames)) < 6 or (shared < 4 and (delta is None or delta > 12)):
            raise SystemExit("Insufficient matching rendered frames")
    finally:
        for directory in directories:
            directory.close()


if __name__ == "__main__":
    main()

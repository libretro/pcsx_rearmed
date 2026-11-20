"""Compare cold boot checkpoints from before disc I/O through the first interactive screen."""

import argparse
import os
from pathlib import Path

from psxrc_playback import playback, write_png
from psxrc_smoke import parse_tap, raster_difference


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stock", type=Path)
    parser.add_argument("fork", type=Path)
    parser.add_argument("source", type=Path)
    parser.add_argument("psxrc", type=Path)
    parser.add_argument("--system", type=Path, required=True)
    parser.add_argument("--dll-directory", type=Path, action="append", default=[])
    parser.add_argument("--bios", choices=("Auto", "HLE"), default="Auto")
    parser.add_argument("--frame", type=int, action="append", required=True, help="Zero-based frame to capture")
    parser.add_argument("--tap", type=parse_tap, action="append", default=[])
    parser.add_argument("--capture-dir", type=Path, required=True)
    parser.add_argument("--match-frame", type=int, action="append", default=[],
                        help="Require this checkpoint to agree with the source")
    args = parser.parse_args()
    checkpoints = frozenset(args.frame)
    if min(checkpoints) < 0 or not set(args.match_frame).issubset(checkpoints):
        parser.error("Checkpoints must be nonnegative and include every match frame")
    args.capture_dir.mkdir(parents=True, exist_ok=True)
    directories = [os.add_dll_directory(str(directory.resolve())) for directory in args.dll_directory]
    try:
        boots = []
        for label, library, image in (("source", args.stock, args.source), ("psxrc", args.fork, args.psxrc)):
            boot = {}
            playback(library.resolve(), image.resolve(), max(checkpoints) + 1, 12, args.system.resolve(),
                     args.bios, taps=args.tap, startup=boot, checkpoints=checkpoints)
            for frame, (_, pixels) in boot["checkpoints"].items():
                if pixels:
                    write_png(args.capture_dir / f"{frame:05}-{label}.png", pixels)
            boots.append(boot)
        print(f"Disc open and boot setup: source {boots[0]['load_ms']:.1f} ms, "
              f"PSXRC {boots[1]['load_ms']:.1f} ms")
        failed = False
        for frame in sorted(checkpoints):
            before, after = (boot["checkpoints"][frame] for boot in boots)
            difference = raster_difference(before[1], after[1])
            sample = f"RGB mean difference {difference:.2f}/255" if difference is not None else "no comparable raster"
            print(f"Frame {frame}: source {before[0]:.1f} ms, PSXRC {after[0]:.1f} ms, {sample}")
            if frame in args.match_frame and (difference is None or difference > 12):
                failed = True
        if failed:
            raise SystemExit("A required cold-boot checkpoint differed from the source")
    finally:
        for directory in directories:
            directory.close()


if __name__ == "__main__":
    main()

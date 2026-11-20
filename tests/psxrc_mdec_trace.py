"""Trace reconstructed STR frames, guest CD transfers, and the MDEC DMA handoff."""

import argparse
from collections import Counter, defaultdict, deque
from pathlib import Path
import os
import subprocess
import sys

from psxrc_playback import playback
from psxrc_smoke import parse_tap


def summary(path):
    expected = defaultdict(dict)
    coefficients = defaultdict(dict)
    transferred = set()
    recent_transfers = deque(maxlen=64)
    commands = Counter()
    handoffs = {}
    output_bytes = Counter()
    direct = set()
    fallbacks = Counter()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        name, _, data = line.partition(" ")
        if name == "PSXRC_VIDEO_DIRECT":
            direct.add(data.split()[0])
            continue
        if name == "PSXRC_VIDEO_FALLBACK":
            fallbacks[data.split()[-1].split("=", 1)[1]] += 1
            continue
        if name not in {"PSXRC_STR", "PSXRC_DMA0", "PSXRC_DMA1", "PSXRC_DMA3"}:
            continue
        fields = dict(item.split("=", 1) for item in data.split())
        commands[name] += 1
        if name == "PSXRC_STR":
            identity = fields["group"], fields["frame"]
            expected[(fields["words"], fields["hash"])][identity] = fields
            if "coefficients" in fields:
                coefficients[(fields["words"], fields["coefficients"])][identity] = fields
        elif name == "PSXRC_DMA0":
            candidates = expected.get((fields["words"], fields["hash"]), {})
            related = coefficients.get((fields["words"], fields.get("coefficients")), {})
            recent = [frame for frame in candidates.values() if frame["lba"] in recent_transfers]
            observed = [frame for frame in candidates.values() if frame["lba"] in transferred]
            handoffs[fields["id"]] = fields, list(candidates.values()), list(related.values()), recent, observed
        elif name == "PSXRC_DMA1":
            output_bytes[fields["id"]] += int(fields["bytes"])
        else:
            transferred.add(fields["lba"])
            recent_transfers.append(fields["lba"])
    matches = [(seq, dma, items[0]) for seq, (dma, items, _, _, _) in handoffs.items() if len(items) == 1]
    ambiguous = sum(len(items) > 1 for _, items, _, _, _ in handoffs.values())
    narrowed = sum(len(items) > 1 and len(recent) == 1 for _, items, _, recent, _ in handoffs.values())
    corroborated = sum(len(items) == 1 and len(observed) == 1 for _, items, _, _, observed in handoffs.values())
    quant_only = Counter((related[0]["quant"], dma["quant_min"], dma["quant_max"])
                         for dma, items, related, _, _ in handoffs.values() if not items and len(related) == 1)
    geometry_matches = 0
    for seq, dma, frame in matches:
        width, height = map(int, frame["size"].split("x"))
        macroblocks = (width + 15) // 16 * ((height + 15) // 16)
        geometry_matches += output_bytes[seq] == macroblocks * 256 * (2 if dma["mode"] == "15" else 3)
    print(f"{commands['PSXRC_STR']} reconstructed frames, {commands['PSXRC_DMA3']} STR CD DMA transfers, "
          f"{commands['PSXRC_DMA0']} MDEC input commands")
    print(f"{len(matches)} unique exact fingerprints, {ambiguous} ambiguous, "
          f"{len(handoffs) - len(matches) - ambiguous} unmatched")
    print(f"{geometry_matches} exact matches had the expected total MDEC output size. "
          f"{corroborated} also transferred the logged disc LBA before the MDEC upload.")
    print(f"Recent CD DMA narrowed {narrowed} ambiguous matches to one candidate.")
    if quant_only:
        print(f"Coefficient-only matches by (expected quantizer, observed min, observed max): {dict(quant_only)}")
    print(f"Matched bitstream versions: {dict(Counter(frame['bs'] for _, _, frame in matches))}")
    print(f"Direct output: {len(direct)} MDEC commands. Guarded fallbacks: {dict(fallbacks)}.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("core", type=Path)
    parser.add_argument("image", type=Path)
    parser.add_argument("--system", required=True, type=Path)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--frames", type=int, default=2200)
    parser.add_argument("--bios", choices=("Auto", "HLE"), default="Auto")
    parser.add_argument("--readahead", choices=(0, 12), type=int, default=12)
    parser.add_argument("--dll-directory", type=Path, action="append", default=[])
    parser.add_argument("--tap", type=parse_tap, action="append", default=[])
    parser.add_argument("--direct-h264", action="store_true")
    parser.add_argument("--reload-state", action="store_true")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.frames < 1:
        parser.error("--frames must be positive")
    if not args.worker:
        args.trace.parent.mkdir(parents=True, exist_ok=True)
        with args.trace.open("wb") as output:
            subprocess.run([sys.executable, str(Path(__file__).resolve()), *sys.argv[1:], "--worker"],
                           stdout=output, stderr=subprocess.STDOUT,
                           env={**os.environ, "PSXRC_TRACE_MDEC": "1"}, check=True)
        summary(args.trace)
        return
    directories = [os.add_dll_directory(str(directory.resolve())) for directory in args.dll_directory]
    try:
        playback(args.core.resolve(), args.image.resolve(), args.frames, args.readahead,
                 args.system.resolve(), args.bios, taps=args.tap, direct_h264=args.direct_h264,
                 reload_state=args.reload_state)
    finally:
        for directory in directories:
            directory.close()


if __name__ == "__main__":
    main()

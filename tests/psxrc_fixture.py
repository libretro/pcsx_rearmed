"""Build a bootable STR comparison disc with PSn00bSDK v0.24 and generated media."""

import argparse
import os
from pathlib import Path
import subprocess


SECTOR_BYTES = 2352
MIXED_BYTES = 2336
STR_SIGNATURE = bytes.fromhex("60010180")

QUANT_UPLOAD = """
    DecDCTReset(1);
    static uint32_t quant[32];
    for (int i = 0; i < 32; ++i) quant[i] = 0x10101010;
    quant[0] = quant[16] = 0x10101002;
    MDEC0 = 0x40000001;
    DecDCTinRaw(quant, 32);
    while (DMA_CHCR(DMA_MDEC_IN) & 0x01000000) __asm__ volatile("");
"""

# The standard PS1 MDEC table in hardware upload order.
STANDARD_QUANT = bytes((
    2, 16, 16, 19, 16, 19, 22, 22, 22, 22, 22, 22, 26, 24, 26, 27,
    27, 27, 26, 26, 26, 26, 27, 27, 27, 29, 29, 29, 34, 34, 34, 29,
    29, 29, 27, 27, 29, 29, 32, 32, 34, 34, 37, 38, 37, 35, 35, 34,
    35, 38, 38, 40, 40, 40, 48, 48, 46, 46, 56, 56, 58, 69, 69, 83,
))

ISO_PROJECT = """<iso_project image_name="original.bin" cue_sheet="original.cue">
  <track type="data">
    <identifiers system="PLAYSTATION" volume="PSXRCTEST" application="PLAYSTATION" />
    <directory_tree>
      <file name="SYSTEM.CNF" type="data" source="system.cnf" />
      <file name="STRVIDEO.EXE" type="data" source="strvideo.exe" />
      <file name="VIDEO.STR" type="mixed" source="video.raw" />
      <dummy sectors="300"/>
    </directory_tree>
  </track>
</iso_project>
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sdk", type=Path, help="PSn00bSDK v0.24 install directory")
    parser.add_argument("toolchain", type=Path, help="MIPS compiler prefix directory")
    parser.add_argument("converter", type=Path, help="psxrc executable")
    parser.add_argument("maker", type=Path, help="psxrc_make_str executable")
    parser.add_argument("output", type=Path, help="New output directory")
    parser.add_argument("--bs-version", choices=("2", "3"), default="2")
    parser.add_argument("--xa-maker", type=Path, help="Interleave a generated XA stream with the movie")
    parser.add_argument("--standard-mdec-quant", action="store_true")
    parser.add_argument("--mdec-hints", action="store_true")
    parser.add_argument("--cmake", default="cmake")
    parser.add_argument("--ninja", help="Ninja executable, if outside PATH")
    args = parser.parse_args()
    sdk, toolchain, output = (p.resolve() for p in (args.sdk, args.toolchain, args.output))
    example = sdk / "share/psn00bsdk/examples/mdec/strvideo"
    source = (example / "main.c").read_text(encoding="utf-8")
    if source.count("DecDCTReset(0);") != 1:
        raise RuntimeError("Expected the PSn00bSDK v0.24 STR player example")
    # Wait explicitly for the quantization DMA so the stock emulator gets both tables.
    upload = QUANT_UPLOAD
    if args.standard_mdec_quant:
        words = [f"0x{int.from_bytes(STANDARD_QUANT[i:i+4], 'little'):08x}" for i in range(0, 64, 4)]
        init = f"    static uint32_t quant[32] = {{ {', '.join(words * 2)} }};\n"
        start = upload.index("    static uint32_t quant")
        end = upload.index("    MDEC0")
        upload = upload[:start] + init + upload[end:]
    source = source.replace("DecDCTReset(0);", upload)
    output.mkdir()
    guest = output / "guest"
    guest.mkdir()
    (guest / "main.c").write_text(source, encoding="utf-8")
    (guest / "CMakeLists.txt").write_bytes((example / "CMakeLists.txt").read_bytes())
    (output / "system.cnf").write_bytes((example / "system.cnf").read_bytes())
    (output / "disc.xml").write_text(ISO_PROJECT, encoding="ascii")
    env = os.environ.copy()
    env["PATH"] = os.pathsep.join((str(toolchain / "bin"), str(sdk / "bin"), env["PATH"]))

    def run(*argv):
        subprocess.run(argv, cwd=output, env=env, check=True)

    configure = [
        args.cmake, "-S", "guest", "-B", ".", "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
        f"-DPSN00BSDK_TC={toolchain.as_posix()}",
        f"-DCMAKE_TOOLCHAIN_FILE={(sdk / 'lib/libpsn00b/cmake/sdk.cmake').as_posix()}",
    ]
    if args.ninja:
        configure.append(f"-DCMAKE_MAKE_PROGRAM={args.ninja}")
    run(*configure)
    run(args.cmake, "--build", ".")
    run(args.maker.resolve(), "generated.bin", args.bs_version)
    original_media = (output / "generated.bin").read_bytes()
    sectors = [original_media[i:i + SECTOR_BYTES] for i in range(0, len(original_media), SECTOR_BYTES)]
    if args.xa_maker:
        run(args.xa_maker.resolve(), "generated-xa.bin")
        audio = (output / "generated-xa.bin").read_bytes()
        sectors = [s for s in sectors if s[24:28] == STR_SIGNATURE]
        for position, i in enumerate(range(0, len(audio), 8 * SECTOR_BYTES)):
            sectors.insert(1 + position * 8, audio[i:i + SECTOR_BYTES])
    raw_media = b"".join(sector[16:] for sector in sectors)
    (output / "video.raw").write_bytes(raw_media)
    mkpsxiso = sdk / "bin" / ("mkpsxiso.exe" if os.name == "nt" else "mkpsxiso")
    run(mkpsxiso, "-q", "disc.xml")
    raw_disc = (output / "original.bin").read_bytes()
    start = next(i // SECTOR_BYTES for i in range(0, len(raw_disc), SECTOR_BYTES)
                 if raw_disc[i + 24:i + 28] == STR_SIGNATURE)
    sector_range = f"{start}:{len(raw_media) // MIXED_BYTES}"
    run(args.converter.resolve(), "convert", "original.cue", "lossless.psxrc", "--preset", "lossless")
    extra = ("--mdec-hints",) if args.mdec_hints else ()
    run(args.converter.resolve(), "convert", "original.cue", "compressed.psxrc", "--str", sector_range, *extra)
    run(args.converter.resolve(), "extract-bin", "compressed.psxrc", "rebuilt.bin")
    cue = (output / "original.cue").read_text(encoding="ascii")
    (output / "rebuilt.cue").write_text(cue.replace("original.bin", "rebuilt.bin"), encoding="ascii")
    (output / "system").mkdir()
    print(f"STR range {sector_range}")


if __name__ == "__main__":
    main()

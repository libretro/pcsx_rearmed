# PCSX ReCompressed desktop prototype

Use the separate converter repository to build the shared PSXRC reader. Check it out next to this fork as `converter` and build it into `converter/build`, or pass its source and static library paths explicitly. See the converter's README for FFmpeg and Zstandard dependencies.

The desktop prototype uses upstream PCSX ReARMed revision `7b0e8f8fadfbce3d170d195b9d9eecaabfa08c8e` and converter revision `1e814ad4a99a4906b87e18ba3627c306ff1d171e`.

```sh
make -f Makefile.libretro platform=unix ARCH=x86_64 HAVE_PSXRC=1
make -f Makefile.libretro platform=win32 ARCH=x86_64 HAVE_PSXRC=1
```

Use a clean build tree when changing the platform or `HAVE_PSXRC`. The feature build produces `pcsx_recompressed_libretro.so` or `pcsx_recompressed_libretro.dll`. Pass `PSXRC_LDLIBS` with the FFmpeg library search path if it is outside the toolchain's default directories. For the fixed-point Opus build, pass the converter's `build/opus/libopus.a` in place of `-lopus`. On Windows, make the runtime DLLs available to the libretro frontend.

Open an image with the `.psxrc` extension directly, or use an M3U playlist for multiple discs. All regular upstream image formats use their existing reader. The PSXRC reader delivers sectors through the existing synchronous and asynchronous CD paths.

## Playback test

The fixture script builds a bootable disc from the PSn00bSDK v0.24 STR playback example and generated media. It produces a BIN/CUE pair, a lossless PSXRC, a compressed PSXRC, and a rebuilt BIN/CUE pair for comparison in the stock core.

```sh
python tests/psxrc_fixture.py /path/to/psn00bsdk /path/to/mips-toolchain \
  ../converter/build/psxrc ../converter/build/psxrc_make_str ./fixture
python tests/psxrc_playback.py pcsx_recompressed_libretro.so fixture/original.cue \
  fixture/lossless.psxrc fixture/rebuilt.cue fixture/compressed.psxrc --system fixture/system \
  --stock ./pcsx_rearmed_libretro.so
```

The test compares matching movie frames from each pair with CD read-ahead disabled and enabled. Pass `--playlist` with an M3U that lists the original CUE and then the converted PSXRC to exercise a disc swap. Set `--dll-directory` on Windows for dependencies stored beside the build tools. `--capture` writes a frame from the original image to help diagnose guest playback issues.

Use `tests/psxrc_smoke.py` for a source-versus-converted game comparison. It runs both images, reloads a saved state, and compares visible frame samples. Pass repeated `--tap FRAME:LIBRETRO_BUTTON` arguments to reproduce a route through a game's menus.

## Prototype measurements

The balanced preset converted the two supplied discs and verified every virtual sector. The Tomb Raider CHD was produced with `chdman` 0.289, and the Bealphareth baseline was the supplied CHD.

| Disc | CHD bytes | PSXRC bytes | Savings |
| --- | ---: | ---: | ---: |
| Tomb Raider (USA) v1.1 | 311,699,302 | 246,084,997 | 21.1% |
| Bealphareth (English translation) | 384,142,318 | 353,380,055 | 8.0% |

On the Windows x64 test host, the Tomb Raider sample at LBA 550–1149 measured 0.779 ms sequential p95 for CHD and 1.531 ms for PSXRC. Cold reader seek p95 was 0.854 ms for CHD and 4.301 ms for PSXRC. The benchmark uses warm operating-system file caches and a fresh reader for each timed seek. It excludes emulator scheduling.

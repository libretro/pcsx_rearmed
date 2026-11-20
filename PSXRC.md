# PCSX ReCompressed prototype

Use the separate converter repository to build the shared PSXRC reader. Check it out next to this fork as `converter` and build it into `converter/build`, or pass its source and static library paths explicitly. See the converter's README for FFmpeg and Zstandard dependencies.

The initial desktop prototype was based on PCSX ReARMed revision `7b0e8f8fadfbce3d170d195b9d9eecaabfa08c8e`. Use a converter checkout that includes the direct playback reader APIs and `cmake/prepare-reference-opus.cmake` for the builds described here.

```sh
make -f Makefile.libretro platform=unix ARCH=x86_64 HAVE_PSXRC=1
make -f Makefile.libretro platform=win32 ARCH=x86_64 HAVE_PSXRC=1
```

Use a clean build tree when changing the platform or `HAVE_PSXRC`. The feature build produces `pcsx_recompressed_libretro.so` or `pcsx_recompressed_libretro.dll`. Pass `PSXRC_LDLIBS` with the FFmpeg library search path if it is outside the toolchain's default directories. For the fixed-point Opus build, pass the converter's `build/opus/libopus.a` in place of `-lopus`. On Windows, make the runtime DLLs available to the libretro frontend.

Open an image with the `.psxrc` extension directly, or use an M3U playlist for multiple discs. All regular upstream image formats use their existing reader. The PSXRC reader delivers sectors through the existing synchronous and asynchronous CD paths.

Under **Core Options → System**, enable **PSXRC Direct XA Audio (Restart)** and reopen the disc to test Opus playback through the CD audio mixer. The option defaults to disabled. It preserves CD filtering, guest DMA and FIFO sector reads, and the save-state layout. XA payloads are reconstructed on demand for guest reads. CDDA already uses PCM after Opus decoding.

Enable **PSXRC Direct H.264 Video (Restart)** in the same menu and reopen the disc to test direct video. The option defaults to disabled. It uses H.264 pixels for an MDEC command when one recent STR frame transfer matches the command's exact run-length words, quantization tables, and macroblock layout. Other commands use the reconstructed STR and normal MDEC output. Game code still receives reconstructed sectors and runs its own bitstream decoder. The prototype bypasses the final MDEC pixel decode for matched blocks, while preserving guest DMA scheduling, sizes, and output packing.

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

Pass `--xa-maker` to the fixture builder with the converter's `psxrc_make_xa` executable to interleave known XA audio. For an A/B check, pass the same core and PSXRC image as both inputs to `psxrc_smoke.py`, with `--direct-xa` to require that the second run used the Opus-to-PCM path. Use `--readahead 0` or `--readahead 12` to exercise both cache configurations.

Use `tests/psxrc_startup.py` to compare a fresh boot of the source and converted images without loading a save state. It measures from before `retro_load_game`, captures both images at each requested `--frame`, and can check raster similarity at selected `--match-frame` checkpoints. Use `--tap` to continue from the title screen into gameplay, then inspect the captures to confirm the intended scene. The reported host times come from unthrottled emulation. Frame numbers identify equivalent points in the scripted boot.

## Direct video handoff

Standard STR movies cross three emulated DMA channels. DMA3 copies reconstructed CD sectors to guest RAM. The game assembles the movie frame and expands the BS bitstream in its own code. DMA0 carries the resulting run-length coefficients to MDEC. DMA1 copies decoded blocks to guest RAM. A DMA0 address therefore identifies a guest buffer whose relationship to a disc LBA depends on the game.

The opt-in `PSXRC_TRACE_MDEC=1` diagnostics record the exact run-length fingerprint expected from a reconstructed frame, the STR sectors transferred through DMA3, and the observed DMA0 and DMA1 activity. The trace runner sets the environment variable in its child process and summarizes the log.

```sh
python tests/psxrc_mdec_trace.py pcsx_recompressed_libretro.dll game.psxrc \
  --system ./system --dll-directory ./runtime --frames 2600 --trace ./game-mdec.log \
  --direct-h264
```

In the Windows checks, all 3,173 retail MDEC input commands matched at least one reconstructed frame across Tomb Raider, Bealphareth, Silent Hill, Ace Combat 2, Guilty Gear, and Moto Racer. 3,064 had one exact fingerprint match. All of those also had a prior CD DMA from the logged disc LBA. The 64-transfer history narrowed 36 of the 109 ambiguous matches. Total output size matched for the 3,063 complete unique matches. The trace ended before the final Ace Combat 2 command finished outputting. With read-ahead disabled, Ace Combat 2 also produced 1,214 unique matches and two ambiguous matches.

The generated BS v2 fixture matched all 58 input commands. The generated BS v3 fixture matched coefficients in all 44 commands after masking the DC-word quantizer bits. Its guest sent quantizers 1 and 3 even though the emitted frame specified 1. An exact match includes these bits.

The 12-byte frame hint is a 64-bit fingerprint and a 32-bit count of unpadded 16-bit run-length words. The converter can store these bytes with each frame using `--mdec-hints`. The core derives the same hint during reconstruction for existing images. A stored hint that disagrees with reconstruction leaves the frame on the regular STR path. Disc changes, resets, and save-state loads clear pending matches.

With the option enabled, the same Windows routes used direct output for 3,068 of 3,173 MDEC commands. The other 105 fell back because more than one recent frame matched. All six games also completed the scripted playback and save-state reload check.

| Game | Direct | Total |
| --- | ---: | ---: |
| Tomb Raider | 362 | 365 |
| Bealphareth | 760 | 780 |
| Silent Hill | 282 | 287 |
| Ace Combat 2 | 1,181 | 1,181 |
| Guilty Gear | 194 | 249 |
| Moto Racer | 289 | 311 |

## Android libretro build

The Android prototype builds a libretro shared library for `arm64-v8a` and `x86_64` with Android API 23 as the minimum build target. It statically links the FFmpeg software H.264 decoder and fixed-point Opus, and uses the core's bundled Zstandard decoder. The library requires an Android libretro frontend.

Run the codec dependency build in Linux or WSL with a Linux Android NDK. The prototype used NDK r30, FFmpeg 8.1, and the matching fixed-point Opus source listed in the converter README.

```sh
bash core/jni/build-psxrc-deps.sh "$NDK" "$FFMPEG_SOURCE" "$OPUS_SOURCE" "$CODEC_PREFIX"
"$NDK/ndk-build" NDK_PROJECT_PATH="$PWD/core" APP_PLATFORM=android-23 \
  APP_ABI="arm64-v8a x86_64" HAVE_PSXRC=1 PSXRC_ROOT="$PWD/converter" \
  PSXRC_ANDROID_DEPS="$CODEC_PREFIX" NDK_LIBS_OUT="$PWD/android-libs"
```

Use absolute paths for `NDK` and `CODEC_PREFIX`. On Windows the second command uses `ndk-build.cmd`, forward slashes for paths, and the same codec prefixes from WSL. The output is `android-libs/<abi>/libpcsx_recompressed_libretro.so`. The source for a minimal ADB smoke frontend is in `tests/psxrc_android_smoke.c`. Generate its disc with `tests/psxrc_fixture.py --standard-mdec-quant --mdec-hints` alongside the normal fixture arguments.

```sh
"$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android23-clang" \
  -O2 -I core/deps/libretro-common/include core/tests/psxrc_android_smoke.c \
  -Wl,-z,max-page-size=16384 -ldl -o android_smoke
remote=/data/local/tmp/psxrc-prototype
adb shell mkdir -p "$remote"
adb push android_smoke "$remote/"
adb push android-libs/x86_64/libpcsx_recompressed_libretro.so "$remote/core.so"
adb push fixture/compressed.psxrc "$remote/fixture.psxrc"
adb shell chmod 755 "$remote/android_smoke"
adb shell "$remote/android_smoke" "$remote/core.so" "$remote/fixture.psxrc" "$remote" 540
adb shell "$remote/android_smoke" "$remote/core.so" "$remote/fixture.psxrc" "$remote" 540 direct
```

Both the Windows and WSL NDK builds passed the x86_64 smoke test on an Android 36.1 emulator. Each run delivered 540 video callbacks and 59 sampled frame changes. Direct output activated only in the explicit opt-in runs. The ARM64 builds were inspected for architecture, libretro exports, and 16 KiB ELF segment alignment. ARM64 device playback is still untested.

## Linux, Windows, and Emscripten cross-builds

From Linux or WSL, `tools/build-psxrc-cross.sh` builds libretro cores for `linux-x86_64`, `linux-i686`, `linux-aarch64`, `linux-armhf`, `windows-i686`, and `emscripten`. Install Make, CMake, and Ninja. For native cores, also install GCC and headers for the target. Use the same FFmpeg and fixed-point Opus sources as for Android. Run the script from a Git checkout with the listed core dependencies present.

```sh
bash core/tools/build-psxrc-cross.sh linux-aarch64 \
  "$FFMPEG_SOURCE" "$OPUS_SOURCE" converter ./out/linux-aarch64
```

Use a separate output directory per ABI. The script builds codecs statically and uses the core's bundled Zstandard decoder. The prototype Linux binaries built with the Ubuntu 26.04 toolchains require glibc 2.43. For an older distribution, build with its compiler and sysroot. The test frontend in `tests/psxrc_android_smoke.c` can load a Linux core under QEMU user mode with the target sysroot, or load the 32-bit Windows core in a 32-bit Windows process.

For `emscripten`, initialize the Emscripten SDK with a writable cache and pass the resulting `pcsx_recompressed_libretro_emscripten.a` to the frontend link. The archive contains the core and PSXRC codecs. The frontend link uses `-sUSE_ZLIB=1 -msimd128`. The browser build uses one thread for core execution and video decoding.

The 32-bit builds select the 64-bit fixed-point arithmetic in a copy of the pinned Opus source. This lets them reconstruct XA and CDDA sectors with the checksums used by the 64-bit converter.

The generated H.264 and XA fixture passed with direct video off and on for each target. Tests ran in native WSL for Linux x86-64, in QEMU user mode for the other Linux ABIs, in a native 32-bit process for Windows x86, and in Node for WebAssembly. The test frontend ran 540 emulated frames per mode.

## Prototype measurements

The balanced preset converted the two supplied discs and verified every virtual sector. The Tomb Raider CHD was produced with `chdman` 0.289, and the Bealphareth baseline was the supplied CHD.

| Disc | CHD bytes | PSXRC bytes | Savings |
| --- | ---: | ---: | ---: |
| Tomb Raider (USA) v1.1 | 311,699,302 | 246,084,997 | 21.1% |
| Bealphareth (English translation) | 384,142,318 | 353,380,055 | 8.0% |

On the Windows x64 test host, the Tomb Raider sample at LBA 550–1149 measured 0.779 ms sequential p95 for CHD and 1.531 ms for PSXRC. Cold reader seek p95 was 0.854 ms for CHD and 4.301 ms for PSXRC. The benchmark uses warm operating-system file caches and a fresh reader for each timed seek. It excludes emulator scheduling.

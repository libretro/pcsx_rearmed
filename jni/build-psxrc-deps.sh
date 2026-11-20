#!/usr/bin/env bash
set -euo pipefail

if (( $# < 4 )); then
    echo "Usage: bash $0 NDK_DIR FFMPEG_SOURCE OPUS_SOURCE OUTPUT [arm64-v8a x86_64]" >&2
    exit 2
fi
ndk=$(realpath "$1")
ffmpeg=$(realpath "$2")
opus=$(realpath "$3")
output=$(realpath -m "$4")
shift 4
if (( $# == 0 )); then
    set -- arm64-v8a x86_64
fi

tools="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin"
api=23
jobs="${PSXRC_JOBS:-6}"
if [[ ! -x "$tools/clang" || ! -f "$ffmpeg/configure" || ! -f "$opus/CMakeLists.txt" ]]; then
    echo "Use a Linux Android NDK and FFmpeg and Opus source checkouts." >&2
    exit 2
fi

# Keep the Autoconf-style build on the Linux filesystem when building in WSL.
work=$(mktemp -d "${TMPDIR:-/tmp}/psxrc-android.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
cp -R "$ffmpeg" "$work/ffmpeg"
cp -R "$opus" "$work/opus"
mkdir -p "$output"

for abi; do
    case "$abi" in
        arm64-v8a) arch=aarch64; triple=aarch64-linux-android ;;
        x86_64) arch=x86_64; triple=x86_64-linux-android ;;
        *) echo "Unsupported prototype ABI: $abi" >&2; exit 2 ;;
    esac
    prefix="$work/install/$abi"
    build="$work/ffmpeg-$abi"
    mkdir -p "$build"
    (
        cd "$build"
        "$work/ffmpeg/configure" \
            --prefix="$prefix" --target-os=android --arch="$arch" --enable-cross-compile \
            --cc="$tools/$triple$api-clang" --ar="$tools/llvm-ar" --ranlib="$tools/llvm-ranlib" \
            --nm="$tools/llvm-nm" --strip="$tools/llvm-strip" \
            --enable-static --disable-shared --enable-pic --disable-debug \
            --disable-doc --disable-programs --disable-avformat --disable-avdevice \
            --disable-avfilter --disable-swresample --disable-swscale \
            --disable-everything --enable-decoder=h264 --disable-network --disable-autodetect \
            --disable-x86asm
        make -j "$jobs"
        make install
    )
    cmake -S "$work/opus" -B "$work/opus-$abi" -G Ninja \
        -DCMAKE_TOOLCHAIN_FILE="$ndk/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI="$abi" -DANDROID_PLATFORM="android-$api" \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$prefix" \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF \
        -DOPUS_FIXED_POINT=ON -DOPUS_DISABLE_INTRINSICS=ON -DOPUS_BUILD_PROGRAMS=OFF
    cmake --build "$work/opus-$abi" --parallel "$jobs"
    cmake --install "$work/opus-$abi"

    mkdir -p "$output/$abi"
    cp -R "$prefix/include" "$prefix/lib" "$output/$abi/"
done

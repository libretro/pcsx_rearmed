#!/usr/bin/env bash
set -euo pipefail

if (( $# != 5 )); then
    echo "Usage: bash $0 TARGET FFMPEG_SOURCE OPUS_SOURCE CONVERTER_SOURCE OUTPUT" >&2
    exit 2
fi

target=$1
platform=unix
system=Linux
extension=so
case "$target" in
    linux-x86_64) arch=x86_64; triple=x86_64-linux-gnu ;;
    linux-i686) arch=i686; triple=i686-linux-gnu ;;
    linux-aarch64) arch=aarch64; triple=aarch64-linux-gnu ;;
    linux-armhf) arch=arm; triple=arm-linux-gnueabihf ;;
    emscripten)
        arch=wasm32
        triple=
        platform=emscripten
        system=Emscripten
        extension=a
        ;;
    windows-i686)
        arch=i686
        triple=i686-w64-mingw32
        platform=win32
        system=Windows
        extension=dll
        ;;
    *) echo "Unsupported target: $target" >&2; exit 2 ;;
esac

core=$(realpath "$(dirname "$0")/..")
ffmpeg=$(realpath "$2")
opus=$(realpath "$3")
converter=$(realpath "$4")
output=$(realpath -m "$5")
jobs=${PSXRC_JOBS:-4}
cc="$triple-gcc"
ar="$triple-ar"
if [[ "$system" == Emscripten ]]; then
    cc=emcc
    ar=emar
fi
command -v "$cc" >/dev/null || { echo "Install $cc to build $target." >&2; exit 2; }
mkdir -p "$output"

# Makefile.libretro writes objects beside the sources. Isolate each architecture.
work=$(mktemp -d "${TMPDIR:-/tmp}/psxrc-$target.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/core" "$work/ffmpeg" "$work/reader"
git -C "$core" ls-files -z --cached --others --exclude-standard |
    tar -c -f - -C "$core" --null -T - |
    tar -x -f - -C "$work/core"
git_dir=$(git -C "$core" rev-parse --absolute-git-dir)
prefix="$work/codecs"

ffmpeg_arch=$arch
if [[ "$arch" == i686 ]]; then
    ffmpeg_arch=x86
fi
ffmpeg_os=linux
ffmpeg_threads=(--enable-pthreads)
ffmpeg_asm=(--disable-x86asm)
ffmpeg_tools=(--cross-prefix="$triple-" --enable-pic)
opus_configure=(cmake)
opus_toolchain=("-DCMAKE_SYSTEM_NAME=$system" "-DCMAKE_SYSTEM_PROCESSOR=$arch" "-DCMAKE_C_COMPILER=$cc"
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON)
system_libs=-lm
if [[ "$system" == Emscripten ]]; then
    ffmpeg_os=none
    ffmpeg_threads=(--disable-pthreads --disable-w32threads)
    ffmpeg_asm=(--disable-asm)
    llvm_root=$(em-config LLVM_ROOT)
    llvm_nm="$llvm_root/llvm-nm"
    if [[ ! -x "$llvm_nm" ]]; then
        llvm_nm="$llvm_nm-$(em-config LLVM_ADD_VERSION)"
    fi
    ffmpeg_tools=(--ar=emar --ranlib=emranlib "--nm=$llvm_nm")
    opus_configure=(emcmake cmake)
    opus_toolchain=()
elif [[ "$system" == Windows ]]; then
    ffmpeg_os=mingw32
    ffmpeg_threads=(--disable-pthreads --enable-w32threads)
    system_libs="-lm -lbcrypt"
    winpthreads=$("$cc" -print-file-name=libwinpthread.a)
    if [[ -f "$winpthreads" ]]; then
        system_libs+=" $winpthreads"
    fi
elif [[ "$arch" == i686 ]]; then
    # FFmpeg's 32-bit inline CABAC assembly can introduce text relocations.
    ffmpeg_asm+=(--disable-inline-asm)
fi
(
    cd "$work/ffmpeg"
    "$ffmpeg/configure" --prefix="$prefix" --target-os="$ffmpeg_os" --arch="$ffmpeg_arch" \
        --enable-cross-compile --cc="$cc" "${ffmpeg_tools[@]}" \
        --enable-static --disable-shared --disable-debug \
        --disable-doc --disable-programs --disable-avformat --disable-avdevice \
        --disable-avfilter --disable-swresample --disable-swscale \
        --disable-everything --enable-decoder=h264 --disable-network --disable-autodetect \
        "${ffmpeg_threads[@]}" "${ffmpeg_asm[@]}"
    make -j "$jobs"
    make install
)

if [[ "$arch" == arm || "$arch" == i686 || "$arch" == wasm32 ]]; then
    cmake "-DPSXRC_OPUS_SOURCE=$opus" "-DPSXRC_OPUS_DESTINATION=$work/opus-source" \
        -P "$converter/cmake/prepare-reference-opus.cmake"
    opus="$work/opus-source"
fi
"${opus_configure[@]}" -S "$opus" -B "$work/opus" -G Ninja "${opus_toolchain[@]}" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$prefix" -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF \
    -DOPUS_FIXED_POINT=ON -DOPUS_DISABLE_INTRINSICS=ON -DOPUS_BUILD_PROGRAMS=OFF
cmake --build "$work/opus" --parallel "$jobs"
cmake --install "$work/opus"

# The core's bundled CHD build supplies the Zstandard decompression symbols.
zstd="$work/core/deps/libchdr/deps/zstd-1.5.7"
reader_objects=()
reader_flags=(-O2 -std=c11)
if [[ "$system" != Emscripten ]]; then
    reader_flags+=(-fPIC)
fi
for source in audio bs codec filters reader str xa; do
    object="$work/reader/$source.o"
    "$cc" "${reader_flags[@]}" -I"$converter/include" -I"$zstd" \
        -I"$prefix/include" -I"$prefix/include/opus" -c "$converter/src/$source.c" -o "$object"
    reader_objects+=("$object")
done
reader="$work/libpsxrc_reader.a"
"$ar" rcs "$reader" "${reader_objects[@]}"

codecs=("$prefix/lib/libavcodec.a" "$prefix/lib/libavutil.a" "$prefix/lib/libopus.a")
export GIT_DIR="$git_dir" GIT_WORK_TREE="$work/core"
build_core=(make -s -C "$work/core" -f Makefile.libretro -j "$jobs"
    "platform=$platform" "ARCH=$arch" "CC=$cc" "AR=$ar" HAVE_PSXRC=1 "PSXRC_ROOT=$converter")
if [[ "$system" == Emscripten ]]; then
    # Store the objects from each library in one archive for the frontend link.
    filename=pcsx_recompressed_libretro_emscripten.a
    "${build_core[@]}" PSXRC_LIB= "TARGET=$work/core.a"
    (
        cd "$work"
        {
            printf 'create %s\n' "$filename"
            printf 'addlib %s\n' core.a libpsxrc_reader.a codecs/lib/libavcodec.a codecs/lib/libavutil.a codecs/lib/libopus.a
            printf 'save\nend\n'
        } | "$ar" -M
    )
else
    filename="pcsx_recompressed_libretro.$extension"
    "${build_core[@]}" "LD=$triple-ld" "PSXRC_LIB=$reader" "TARGET=$work/$filename" \
        "PSXRC_LDLIBS=${codecs[*]} $system_libs"
fi
cp "$work/$filename" "$output/$filename"

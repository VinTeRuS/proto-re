#!/bin/bash
# Minimal static FFmpeg for the Bink movies (src/native/bink.cpp): the bink demuxer and the bink/binkaudio
# decoders only (LGPL build). Called by build-deps.sh; can also be run alone.
#
# Usage: android/build-ffmpeg.sh <abi: arm64-v8a | x86_64> <source dir> <install prefix>
set -euo pipefail

ABI=${1:?abi}
SRC=$(realpath -m "${2:?source dir}")
PREFIX=$(realpath -m "${3:?install prefix}")
NDK=${ANDROID_NDK_HOME:-${ANDROID_NDK_LATEST_HOME:?set ANDROID_NDK_HOME}}
API=26
JOBS=${JOBS:-$(nproc)}
FFMPEG_TAG=n7.1.1

case $ABI in
    arm64-v8a) TRIPLE=aarch64-linux-android; ARCH=aarch64; ASM=() ;;
    x86_64) TRIPLE=x86_64-linux-android; ARCH=x86_64; ASM=(--disable-x86asm) ;;
    *) echo "unknown ABI $ABI" >&2; exit 2 ;;
esac

TC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
mkdir -p "$SRC"
[ -d "$SRC/ffmpeg" ] || git clone -q --depth 1 --branch $FFMPEG_TAG https://github.com/FFmpeg/FFmpeg.git "$SRC/ffmpeg"
B=$SRC/build/ffmpeg-$ABI
rm -rf "$B" && mkdir -p "$B" && cd "$B"
"$SRC/ffmpeg/configure" --prefix="$PREFIX" --target-os=android --arch=$ARCH --enable-cross-compile \
    --cc="$TC/$TRIPLE$API-clang" --cxx="$TC/$TRIPLE$API-clang++" --nm="$TC/llvm-nm" --ar="$TC/llvm-ar" \
    --ranlib="$TC/llvm-ranlib" --strip="$TC/llvm-strip" --enable-pic --enable-static --disable-shared \
    --disable-everything --disable-programs --disable-doc --disable-network --disable-autodetect \
    --disable-avdevice --disable-avfilter --disable-swscale --disable-swresample \
    --enable-demuxer=bink --enable-decoder=bink,binkaudio_dct,binkaudio_rdft "${ASM[@]}"
make -j "$JOBS"
make install

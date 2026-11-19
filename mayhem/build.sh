#!/usr/bin/env bash
#
# mayhem/build.sh — build the LAVFilters parser fuzz harnesses and the known-answer selftest.
#
# LAVFilters is a Windows-only DirectShow filter set (MSVC solution, no Linux build). The code that
# parses untrusted bytes on its own — the HEVC/H.264 SPS, VC-1, MPEG-2 and MPEG extradata parsers,
# the AnnexB converter, the DTS/AC-3/TrueHD bitstream header parser and the cue sheet parser — is
# portable C++ over FFmpeg's bit reader, so we compile exactly those upstream .cpp files against a
# small Win32 shim (mayhem/shim/stdafx.h) and LAV's FFmpeg fork, prebuilt (uninstrumented, static,
# at the submodule's pinned commit) by mayhem/Dockerfile into $FFMPEG_DEP.
#
# Outputs: /mayhem/fuzz_<name> (libFuzzer), /mayhem/fuzz_<name>-standalone (run-once reproducer),
# /mayhem/mayhem/build/lav_selftest (normal flags; run by mayhem/test.sh).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${FFMPEG_DEP:=/opt/toolchains/deps/ffmpeg-lav-80af591}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
[ -f "$FFMPEG_DEP/lib/libavcodec.a" ] || { echo "missing FFmpeg dependency at $FFMPEG_DEP" >&2; exit 1; }

HARNESSES=(hevc_sps h264_sps bitstream vc1 annexb cuesheet mpeg2 extradata)
B="$SRC/mayhem/build"   # gitignored (mayhem/.gitignore)
S="$B/src"

# 1) Source tree view: each upstream file is symlinked next to the shim stdafx.h, so its
#    `#include "stdafx.h"` picks the shim, not the Windows header beside the original. Recreated
#    every run (idempotent).
rm -rf "$S" && mkdir -p "$S/parser" "$B/obj"
UPSTREAM_SRCS=(
  common/DSUtilLite/ByteParser.cpp common/DSUtilLite/H264Nalu.cpp common/DSUtilLite/CueSheet.cpp
  decoder/LAVVideo/parsers/AnnexBConverter.cpp decoder/LAVVideo/parsers/H264SequenceParser.cpp
  decoder/LAVVideo/parsers/HEVCSequenceParser.cpp decoder/LAVVideo/parsers/MPEG2HeaderParser.cpp
  decoder/LAVVideo/parsers/VC1HeaderParser.cpp decoder/LAVAudio/BitstreamParser.cpp
  demuxer/Demuxers/ExtradataParser.cpp
)
for f in "${UPSTREAM_SRCS[@]}"; do
  ln -s "$SRC/$f" "$S/"
  ln -s "$SRC/${f%.cpp}.h" "$S/"
done
# H264Nalu.cpp's `goto notfound` jumps over `size_t nBuffEnd = m_nSize - 4;`, which MSVC accepts and
# standard C++ rejects. Compile a generated copy with that one line split into declaration +
# assignment (same line, same behavior); `#line` keeps debug info and backtraces on the original.
rm "$S/H264Nalu.cpp"
{ echo "#line 1 \"$SRC/common/DSUtilLite/H264Nalu.cpp\""
  sed 's/^\(\s*\)size_t nBuffEnd = m_nSize - 4;/\1size_t nBuffEnd; nBuffEnd = m_nSize - 4;/' \
    "$SRC/common/DSUtilLite/H264Nalu.cpp"; } > "$S/H264Nalu.cpp"
grep -q 'size_t nBuffEnd; nBuffEnd = m_nSize - 4;' "$S/H264Nalu.cpp" \
  || { echo "H264Nalu.cpp no longer matches the goto workaround; update mayhem/build.sh" >&2; exit 1; }
for f in decoder/LAVAudio/parser/*; do ln -s "$SRC/$f" "$S/parser/"; done
ln -s ByteParser.h "$S/byteparser.h"   # ExtradataParser.h includes it lowercase (case-insensitive on Windows)
ln -s "$SRC/mayhem/shim/stdafx.h" "$S/stdafx.h"
LAV_SRCS=(ByteParser H264Nalu CueSheet AnnexBConverter H264SequenceParser HEVCSequenceParser
          MPEG2HeaderParser VC1HeaderParser BitstreamParser ExtradataParser parser/dts)

INC=(-I"$S" -I"$SRC/mayhem/harnesses" -I"$FFMPEG_DEP/include" -I"$FFMPEG_DEP/src")
# -fms-extensions: MSVC's `i64` integer suffix (CueSheet.cpp). -w: the sources are MSVC-clean, not
# clang-warning-clean, and FFmpeg's get_bits.h uses `register` (an error-level warning in C++17).
CXXSTD=(-std=c++17 -fms-extensions -w -Wno-register)
FFLIBS=("$FFMPEG_DEP/lib/libavcodec.a" "$FFMPEG_DEP/lib/libavutil.a" -lm -lpthread)

# compile_set <dir> <flags...>: compile the upstream sources into $B/obj/<dir>.
compile_set() {
  local dir="$B/obj/$1"; shift
  mkdir -p "$dir/parser"
  local pids=() f
  for f in "${LAV_SRCS[@]}"; do
    $CXX "${CXXSTD[@]}" "$@" "${INC[@]}" -c "$S/$f.cpp" -o "$dir/$f.o" &
    pids+=($!)
    if [ "${#pids[@]}" -ge "$MAYHEM_JOBS" ]; then wait "${pids[0]}"; pids=("${pids[@]:1}"); fi
  done
  for p in "${pids[@]}"; do wait "$p"; done
}
objs() { local d="$B/obj/$1" f; for f in "${LAV_SRCS[@]}"; do echo "$d/$f.o"; done; }

# 2) Fuzz build: the upstream parsers AND the harnesses instrumented with sanitizers + coverage.
#    UBSan's `enum` check is relaxed (everything else stays on and halting): CH265Nalu deliberately
#    reuses CH264Nalu, whose NALU_TYPE enum only spans the 5-bit H.264 NAL types, to carry 6-bit
#    HEVC types (VPS = 32 ...), so every HEVC stream would trip it on its first NAL.
#    UBSan's `alignment` check is relaxed too: CH264Nalu::MoveToNextAnnexBStartcode
#    (H264Nalu.cpp:50) scans for start codes with a deliberate unaligned `*(DWORD *)(buf + i)` load
#    at every byte offset (the x86/MSVC idiom; it reads within bounds, which ASan still checks), so
#    every AnnexB input would halt there before the SPS/VUI parsers run.
RELAX=(-fno-sanitize=enum,alignment)
FUZZ_FLAGS=($SANITIZER_FLAGS "${RELAX[@]}" $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link)
SA_FLAGS=($SANITIZER_FLAGS "${RELAX[@]}" $DEBUG_FLAGS -O1)
compile_set fuzz "${FUZZ_FLAGS[@]}"
compile_set standalone "${SA_FLAGS[@]}"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/obj/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/obj/standalone_main.o"
mapfile -t FUZZ_OBJS < <(objs fuzz)
mapfile -t SA_OBJS < <(objs standalone)
for h in "${HARNESSES[@]}"; do
  $CXX "${CXXSTD[@]}" "${FUZZ_FLAGS[@]}" "${INC[@]}" -c "$SRC/mayhem/harnesses/fuzz_$h.cpp" -o "$B/obj/fuzz_$h.o"
  $CXX "${CXXSTD[@]}" "${SA_FLAGS[@]}" "${INC[@]}" -c "$SRC/mayhem/harnesses/fuzz_$h.cpp" -o "$B/obj/fuzz_$h.sa.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/obj/fuzz_$h.o" "${FUZZ_OBJS[@]}" \
    "$B/obj/lsan_off.o" "${FFLIBS[@]}" -o "$SRC/fuzz_$h"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/obj/standalone_main.o" "$B/obj/fuzz_$h.sa.o" "${SA_OBJS[@]}" \
    "$B/obj/lsan_off.o" "${FFLIBS[@]}" -o "$SRC/fuzz_$h-standalone"
done

# 3) Known-answer selftest, NORMAL flags (no sanitizers), for mayhem/test.sh.
compile_set test -O2 $COVERAGE_FLAGS
mapfile -t TEST_OBJS < <(objs test)
$CXX "${CXXSTD[@]}" -O2 $COVERAGE_FLAGS "${INC[@]}" "$SRC/mayhem/selftest/lav_selftest.cpp" "${TEST_OBJS[@]}" \
  "${FFLIBS[@]}" $COVERAGE_FLAGS -o "$B/lav_selftest"

ls -l "${HARNESSES[@]/#/$SRC/fuzz_}" "$B/lav_selftest"

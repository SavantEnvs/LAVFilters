// mayhem/shim/stdafx.h — Linux stand-in for LAVFilters' Windows precompiled header.
//
// LAVFilters builds only with MSVC against the Windows SDK; the parsers fuzzed here are plain C++
// over FFmpeg's bit reader, so this header supplies just the handful of Win32 typedefs/macros they
// use. build.sh symlinks each fuzzed upstream .cpp next to this file so `#include "stdafx.h"`
// resolves here instead of to the Windows header beside the source.
#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <climits>
#include <string>
#include <algorithm>

typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef int BOOL;
typedef int32_t HRESULT;
typedef int64_t REFERENCE_TIME;

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif
#define S_OK ((HRESULT)0)
#define S_FALSE ((HRESULT)1)
#define E_FAIL ((HRESULT)0x80004005)
#define E_POINTER ((HRESULT)0x80004003)
#define E_OUTOFMEMORY ((HRESULT)0x8007000E)
#define E_INVALIDARG ((HRESULT)0x80070057)
#define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)
#define FAILED(hr) (((HRESULT)(hr)) < 0)
#define CheckPointer(p, ret) \
    {                        \
        if ((p) == nullptr)  \
            return (ret);    \
    }
// DirectShow debug macros: compiled out, as in an MSVC release build.
#define ASSERT(x) ((void)0)
#define DbgLog(x) ((void)0)
#define ZeroMemory(p, n) memset((p), 0, (n))
#define sscanf_s sscanf
#define __declspec(x)
// MSVC CRT aligned allocation (H264Nalu.cpp's unescape buffer); posix_memalign keeps ASan tracking it.
static inline void *_aligned_malloc(size_t size, size_t alignment)
{
    void *p = nullptr;
    return posix_memalign(&p, alignment, size) == 0 ? p : nullptr;
}
static inline void _aligned_free(void *p)
{
    free(p);
}
using std::max;
using std::min;

extern "C"
{
#define __STDC_CONSTANT_MACROS
#include "libavcodec/avcodec.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/mem.h"
#include "libavutil/mathematics.h"
}

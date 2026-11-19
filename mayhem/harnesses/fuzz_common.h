// Shared helpers for the LAVFilters parser harnesses.
#pragma once
#include "stdafx.h"
#include <vector>

// Every buffer LAVFilters hands to these parsers comes from FFmpeg (AVPacket data, codecpar
// extradata), which guarantees AV_INPUT_BUFFER_PADDING_SIZE zeroed bytes past the end; the bit
// readers rely on that. Mirror the contract, nothing more: the payload is copied into a heap block
// of exactly size + padding, so a read past the padding is still an ASan report.
struct PaddedBuffer
{
    BYTE *data;
    size_t size;
    PaddedBuffer(const uint8_t *src, size_t n) : size(n)
    {
        data = (BYTE *)malloc(n + AV_INPUT_BUFFER_PADDING_SIZE);
        if (n)
            memcpy(data, src, n);
        memset(data + n, 0, AV_INPUT_BUFFER_PADDING_SIZE);
    }
    ~PaddedBuffer() { free(data); }
    PaddedBuffer(const PaddedBuffer &) = delete;
    PaddedBuffer &operator=(const PaddedBuffer &) = delete;
};

// H.264 sequence parser: CH264SequenceParser::ParseNALs over codec extradata / packets, as
// LAVVideo does to read profile, level, chroma format and bit depth of an H.264 stream (SPS, VUI, scaling lists).
// Byte 0 selects the NAL framing LAVVideo passes (0 = Annex B start codes, else the length-prefix
// size from avcC: 1, 2 or 4); the rest is the bitstream.
#include "fuzz_common.h"
#include "H264SequenceParser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return -1;
    static const int kNalSizes[4] = {0, 1, 2, 4};
    int nal_size = kNalSizes[data[0] & 3];
    PaddedBuffer buf(data + 1, size - 1);
    CH264SequenceParser parser;
    parser.ParseNALs(buf.data, buf.size, nal_size);
    return 0;
}

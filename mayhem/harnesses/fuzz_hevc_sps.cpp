// HEVC sequence parser: CHEVCSequenceParser::ParseNALs over codec extradata / packets, as
// LAVVideo does to read profile, level, chroma format and bit depth of an HEVC stream.
// Byte 0 selects the NAL framing LAVVideo passes (0 = Annex B start codes, else the length-prefix
// size from hvcC: 1, 2 or 4); the rest is the bitstream.
#include "fuzz_common.h"
#include "HEVCSequenceParser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return -1;
    static const int kNalSizes[4] = {0, 1, 2, 4};
    int nal_size = kNalSizes[data[0] & 3];
    PaddedBuffer buf(data + 1, size - 1);
    CHEVCSequenceParser parser;
    parser.ParseNALs(buf.data, buf.size, nal_size);
    return 0;
}

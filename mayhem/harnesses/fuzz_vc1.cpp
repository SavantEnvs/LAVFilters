// VC-1 / WMV3 header parser: CVC1HeaderParser parses the sequence header from codec extradata
// (LAVVideo, WMV9 MFT decoder), then ParseVC1PictureType reads each packet's picture type.
// Byte 0 picks VC-1 or WMV3, bytes 1-2 the extradata length; the rest is the packet.
#include "fuzz_common.h"
#include "VC1HeaderParser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 3)
        return -1;
    AVCodecID codec = (data[0] & 1) ? AV_CODEC_ID_WMV3 : AV_CODEC_ID_VC1;
    size_t extra_len = ((size_t)data[1] << 8 | data[2]);
    data += 3;
    size -= 3;
    if (extra_len > size)
        extra_len = size;

    PaddedBuffer extra(data, extra_len);
    PaddedBuffer frame(data + extra_len, size - extra_len);
    CVC1HeaderParser parser(extra.data, extra.size, codec);
    parser.ParseVC1PictureType(frame.data, (int)frame.size);
    return 0;
}

// AnnexB converter: CAnnexBConverter turns length-prefixed (avcC/hvcC) NAL units into Annex B
// start-code form for the hardware decoders (cuvid), and walks an hvcC extradata record's NAL
// arrays in ConvertHEVCExtradata. Byte 0: bit 2 selects ConvertHEVCExtradata, bits 0-1 the NALU
// length size 1..4 (avcC lengthSizeMinusOne + 1) for Convert.
#include "fuzz_common.h"
#include "AnnexBConverter.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return -1;
    uint8_t mode = data[0];
    PaddedBuffer in(data + 1, size - 1);
    if (in.size > INT_MAX)
        return -1;

    CAnnexBConverter conv;
    BYTE *out = nullptr;
    int out_size = 0;
    if (mode & 4)
    {
        conv.ConvertHEVCExtradata(&out, &out_size, in.data, (int)in.size);
    }
    else
    {
        conv.SetNALUSize((mode & 3) + 1);
        conv.Convert(&out, &out_size, in.data, (int)in.size);
    }
    av_freep(&out);
    return 0;
}

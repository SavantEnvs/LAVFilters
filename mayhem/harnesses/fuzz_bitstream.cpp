// Audio bitstream header parser: CBitstreamParser::Parse, which LAVAudio runs on every frame it
// passes through (bitstreaming) to read the DTS / DTS-HD, AC-3 / E-AC-3 and TrueHD headers.
// Byte 0 picks the codec, byte 1 splits the rest into two consecutive frames so the parser's
// per-stream state (DTS parser context, sample rate) carries from one frame to the next, as it
// does in a real stream.
#include "fuzz_common.h"
#include "BitstreamParser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
        return -1;
    static const AVCodecID kCodecs[4] = {AV_CODEC_ID_DTS, AV_CODEC_ID_AC3, AV_CODEC_ID_EAC3, AV_CODEC_ID_TRUEHD};
    AVCodecID codec = kCodecs[data[0] & 3];
    data += 2;
    size -= 2;
    size_t first = size * data[-1] / 255;

    CBitstreamParser parser;
    {
        PaddedBuffer f1(data, first);
        parser.Parse(codec, f1.data, (DWORD)f1.size);
    }
    {
        PaddedBuffer f2(data + first, size - first);
        parser.Parse(codec, f2.data, (DWORD)f2.size);
    }
    return 0;
}

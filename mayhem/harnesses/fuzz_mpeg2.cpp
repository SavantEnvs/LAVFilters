// MPEG-2 header parser: CMPEG2HeaderParser finds the sequence header and sequence extension in
// codec extradata, as LAVVideo does to pick profile, level, chroma format and interlacing.
#include "fuzz_common.h"
#include "MPEG2HeaderParser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    PaddedBuffer buf(data, size);
    CMPEG2HeaderParser parser(buf.data, buf.size);
    (void)parser.hdr.valid;
    return 0;
}

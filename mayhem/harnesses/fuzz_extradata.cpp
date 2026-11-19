// MPEG-1/2 extradata parser: CExtradataParser::ParseMPEGSequenceHeader scans the demuxed
// extradata for the sequence header (+ extension) and copies it into the DirectShow media type.
// The callers (LAVFVideoHelper.cpp, LAVFDemuxer.cpp) size that destination from the extradata
// length: MPEG2VIDEOINFO's dwSequenceHeader holds max(extra, 4) bytes, which is the tightest of
// them, so the harness gives the parser exactly that.
#include "fuzz_common.h"
#include "ExtradataParser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    PaddedBuffer buf(data, size);
    size_t cap = size > 4 ? size : 4;
    BYTE *target = (BYTE *)malloc(cap);
    CExtradataParser parser(buf.data, buf.size);
    (void)parser.ParseMPEGSequenceHeader(target);
    free(target);
    return 0;
}

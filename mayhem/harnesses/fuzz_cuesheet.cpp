// Cue sheet parser: CCueSheet::Parse reads the CUESHEET text a container (FLAC, Matroska, APE)
// embeds in its metadata; LAVSplitter turns each track into a chapter via FormatTrack.
#include "fuzz_common.h"
#include "CueSheet.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    CCueSheet cue;
    if (FAILED(cue.Parse(std::string((const char *)data, size))))
        return 0;
    for (auto &track : cue.m_Tracks)
        (void)cue.FormatTrack(track);
    return 0;
}

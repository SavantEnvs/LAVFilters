// mayhem/selftest/lav_selftest.cpp — known-answer tests for the LAVFilters parsers the harnesses fuzz.
//
// Upstream ships no tests (it is a Windows DirectShow filter set), so this suite is the functional
// oracle for mayhem/test.sh: each case feeds a bitstream whose header fields are known (hand-decoded
// bytes, or built here field-by-field with a bit writer) and asserts the values the parser reports.
// Prints one "PASS <name>" / "FAIL <name>: ..." line per case; exit status 1 if any case failed.
#include "stdafx.h"
#include <vector>
#include <list>

#include "AnnexBConverter.h"
#include "BitstreamParser.h"
#include "CueSheet.h"
#include "ExtradataParser.h"
#include "H264SequenceParser.h"
#include "HEVCSequenceParser.h"
#include "MPEG2HeaderParser.h"
#include "VC1HeaderParser.h"

typedef std::vector<uint8_t> Bytes;

static int g_failed = 0;
static int g_passed = 0;
static bool g_case_ok;
static const char *g_case;

#define CHECK_EQ(actual, expected)                                                                    \
    do                                                                                                \
    {                                                                                                 \
        long long a_ = (long long)(actual), e_ = (long long)(expected);                               \
        if (a_ != e_)                                                                                 \
        {                                                                                             \
            printf("FAIL %s: %s = %lld, expected %lld\n", g_case, #actual, a_, e_);                   \
            g_case_ok = false;                                                                        \
        }                                                                                             \
    } while (0)
#define CHECK_STR(actual, expected)                                                                   \
    do                                                                                                \
    {                                                                                                 \
        std::string a_ = (actual), e_ = (expected);                                                   \
        if (a_ != e_)                                                                                 \
        {                                                                                             \
            printf("FAIL %s: %s = \"%s\", expected \"%s\"\n", g_case, #actual, a_.c_str(), e_.c_str()); \
            g_case_ok = false;                                                                        \
        }                                                                                             \
    } while (0)

static void begin(const char *name)
{
    g_case = name;
    g_case_ok = true;
}
static void end()
{
    if (g_case_ok)
    {
        printf("PASS %s\n", g_case);
        g_passed++;
    }
    else
        g_failed++;
}

// MSB-first bit writer with H.264/HEVC exp-Golomb codes.
struct BitWriter
{
    Bytes out;
    int bits = 0;
    void u(uint64_t v, int n)
    {
        for (int i = n - 1; i >= 0; i--)
        {
            if (bits % 8 == 0)
                out.push_back(0);
            if ((v >> i) & 1)
                out.back() |= 0x80 >> (bits % 8);
            bits++;
        }
    }
    void ue(uint32_t v)
    {
        uint64_t x = (uint64_t)v + 1;
        int len = 0;
        while ((x >> len) > 1)
            len++;
        u(0, len);
        u(x, len + 1);
    }
    Bytes finish() // rbsp_trailing_bits
    {
        u(1, 1);
        while (bits % 8)
            u(0, 1);
        return out;
    }
};

// Insert emulation-prevention bytes (00 00 0x -> 00 00 03 0x).
static Bytes escape(const Bytes &rbsp)
{
    Bytes o;
    int zeros = 0;
    for (uint8_t b : rbsp)
    {
        if (zeros >= 2 && b <= 3)
        {
            o.push_back(3);
            zeros = 0;
        }
        o.push_back(b);
        zeros = b ? 0 : zeros + 1;
    }
    return o;
}
static void append(Bytes &dst, const Bytes &src)
{
    dst.insert(dst.end(), src.begin(), src.end());
}
static Bytes annexb(const Bytes &nal)
{
    Bytes o = {0, 0, 0, 1};
    append(o, nal);
    return o;
}
static Bytes lenprefix(const Bytes &nal, int n)
{
    Bytes o;
    for (int i = n - 1; i >= 0; i--)
        o.push_back((uint8_t)(nal.size() >> (8 * i)));
    append(o, nal);
    return o;
}
static Bytes padded(const Bytes &b)
{
    Bytes o = b;
    o.resize(b.size() + AV_INPUT_BUFFER_PADDING_SIZE, 0);
    return o;
}

// HEVC SPS NAL (type 33) with the given profile_idc / compatibility flag / level / chroma / bit depth.
static Bytes hevc_sps(int profile_idc, int compat_flag, int level, int chroma, int bitdepth)
{
    BitWriter w;
    w.u(0, 4); // sps_video_parameter_set_id
    w.u(0, 3); // sps_max_sub_layers_minus1
    w.u(1, 1); // sps_temporal_id_nesting_flag
    w.u(0, 2); // general_profile_space
    w.u(0, 1); // general_tier_flag
    w.u(profile_idc, 5);
    w.u(compat_flag >= 0 ? (1u << (31 - compat_flag)) : 0, 32);
    w.u(0x9, 4);  // progressive, interlaced=0, non_packed=0, frame_only=1
    w.u(0, 43);   // reserved
    w.u(0, 1);    // reserved_zero_bit
    w.u(level, 8); // general_level_idc
    w.ue(0);       // sps_seq_parameter_set_id
    w.ue(chroma);  // chroma_format_idc
    w.ue(1920);    // pic_width_in_luma_samples
    w.ue(1080);    // pic_height_in_luma_samples
    w.u(0, 1);     // conformance_window_flag
    w.ue(bitdepth - 8);
    w.ue(bitdepth - 8);
    w.ue(4); // log2_max_pic_order_cnt_lsb_minus4
    Bytes nal = {0x42, 0x01}; // nal_unit_type 33, layer 0, tid 1
    append(nal, escape(w.finish()));
    return nal;
}
static Bytes hevc_vps()
{
    return {0x40, 0x01, 0x0c, 0x01, 0xff, 0xff, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00, 0x90};
}

// A real x264 High profile level 3.1 SPS (1280x720), hand-decoded: profile_idc 0x64 = 100,
// level_idc 0x1f = 31, then ue sps_id '1' = 0, ue chroma_format_idc '010' = 1,
// ue bit_depth_luma_minus8 '1' = 0, ue bit_depth_chroma_minus8 '1' = 0.
static const Bytes kH264Sps = {0x67, 0x64, 0x00, 0x1f, 0xac, 0xd9, 0x40, 0x50, 0x05, 0xbb, 0x01, 0x10, 0x00,
                               0x00, 0x03, 0x00, 0x10, 0x00, 0x00, 0x03, 0x03, 0xc0, 0xf1, 0x83, 0x19, 0x60};

static void test_h264()
{
    begin("h264_sps_annexb");
    {
        Bytes in = annexb({0x09, 0xf0}); // access unit delimiter first, must be skipped
        append(in, annexb(kH264Sps));
        Bytes buf = padded(in);
        CH264SequenceParser p;
        p.ParseNALs(buf.data(), in.size(), 0);
        CHECK_EQ(p.sps.valid, 1);
        CHECK_EQ(p.sps.profile, 100);
        CHECK_EQ(p.sps.level, 31);
        CHECK_EQ(p.sps.chroma, 1);
        CHECK_EQ(p.sps.luma_bitdepth, 8);
        CHECK_EQ(p.sps.chroma_bitdepth, 8);
    }
    end();

    begin("h264_sps_length_prefixed");
    {
        Bytes in = lenprefix(kH264Sps, 4);
        Bytes buf = padded(in);
        CH264SequenceParser p;
        p.ParseNALs(buf.data(), in.size(), 4);
        CHECK_EQ(p.sps.valid, 1);
        CHECK_EQ(p.sps.profile, 100);
        CHECK_EQ(p.sps.level, 31);
    }
    end();

    begin("h264_no_sps");
    {
        Bytes in = annexb({0x68, 0xeb, 0xe3, 0xcb, 0x22, 0xc0}); // PPS only
        Bytes buf = padded(in);
        CH264SequenceParser p;
        p.ParseNALs(buf.data(), in.size(), 0);
        CHECK_EQ(p.sps.valid, 0);
    }
    end();
}

static void test_hevc()
{
    begin("hevc_sps_main10_annexb");
    {
        Bytes in = annexb(hevc_vps());
        append(in, annexb(hevc_sps(2, 2, 120, 1, 10)));
        Bytes buf = padded(in);
        CHEVCSequenceParser p;
        p.ParseNALs(buf.data(), in.size(), 0);
        CHECK_EQ(p.sps.valid, 1);
        CHECK_EQ(p.sps.profile, 2);
        CHECK_EQ(p.sps.level, 120);
        CHECK_EQ(p.sps.chroma, 1);
        CHECK_EQ(p.sps.bitdepth, 10);
    }
    end();

    begin("hevc_sps_profile_from_compat_flags");
    {
        // general_profile_idc 0: the parser takes the profile from the first compatibility flag set.
        Bytes in = lenprefix(hevc_sps(0, 1, 93, 2, 8), 2);
        Bytes buf = padded(in);
        CHEVCSequenceParser p;
        p.ParseNALs(buf.data(), in.size(), 2);
        CHECK_EQ(p.sps.valid, 1);
        CHECK_EQ(p.sps.profile, 1);
        CHECK_EQ(p.sps.level, 93);
        CHECK_EQ(p.sps.chroma, 2);
        CHECK_EQ(p.sps.bitdepth, 8);
    }
    end();
}

static void test_mpeg2()
{
    begin("mpeg2_sequence_extension");
    {
        // sequence_header 720x576 + sequence_extension: profile Main (4), level Main (8),
        // progressive_sequence 0 (interlaced), chroma_format 1 (4:2:0).
        Bytes in = {0x00, 0x00, 0x01, 0xb3, 0x2d, 0x02, 0x40, 0x33, 0x24, 0x9f, 0x23, 0x80,
                    0x00, 0x00, 0x01, 0xb5, 0x14, 0x82, 0x00, 0x01, 0x00, 0x00,
                    0x00, 0x00, 0x01, 0xb8, 0x00, 0x08, 0x00, 0x00};
        Bytes buf = padded(in);
        CMPEG2HeaderParser p(buf.data(), in.size());
        CHECK_EQ(p.hdr.valid, 1);
        CHECK_EQ(p.hdr.profile, 4);
        CHECK_EQ(p.hdr.level, 8);
        CHECK_EQ(p.hdr.interlaced, 1);
        CHECK_EQ(p.hdr.chroma, 1);
    }
    end();
}

static void test_extradata()
{
    begin("mpeg_extradata_sequence_header");
    {
        // junk, then sequence header (12 bytes, no matrices) + sequence extension (10 bytes), then GOP.
        Bytes seq = {0x00, 0x00, 0x01, 0xb3, 0x2d, 0x02, 0x40, 0x33, 0x24, 0x9f, 0x23, 0x80};
        Bytes ext = {0x00, 0x00, 0x01, 0xb5, 0x14, 0x82, 0x00, 0x01, 0x00, 0x00};
        Bytes in = {0xaa, 0xbb};
        append(in, seq);
        append(in, ext);
        append(in, {0x00, 0x00, 0x01, 0xb8, 0x00, 0x08, 0x00, 0x00});
        Bytes buf = padded(in);
        Bytes target(in.size(), 0xcc);
        CExtradataParser p(buf.data(), in.size());
        size_t n = p.ParseMPEGSequenceHeader(target.data());
        CHECK_EQ(n, seq.size() + ext.size());
        Bytes expect = seq;
        append(expect, ext);
        CHECK_EQ(memcmp(target.data(), expect.data(), expect.size()) == 0, 1);
    }
    end();

    begin("mpeg_extradata_no_sequence_header");
    {
        Bytes in = {0x00, 0x00, 0x01, 0xb8, 0x00, 0x08, 0x00, 0x00, 0x11, 0x22};
        Bytes buf = padded(in);
        Bytes target(16, 0);
        CExtradataParser p(buf.data(), in.size());
        CHECK_EQ(p.ParseMPEGSequenceHeader(target.data()), 0);
    }
    end();
}

static Bytes vc1_advanced_seqhdr()
{
    BitWriter w;
    w.u(3, 2);   // profile: advanced
    w.u(3, 3);   // level
    w.u(1, 2);   // colordiff_format (4:2:0)
    w.u(7, 3);   // frmrtq_postproc
    w.u(31, 5);  // bitrtq_postproc
    w.u(0, 1);   // postprocflag
    w.u(959, 12); // max_coded_width  -> (959+1)*2 = 1920
    w.u(539, 12); // max_coded_height -> (539+1)*2 = 1080
    w.u(0, 1);   // pulldown/broadcast
    w.u(1, 1);   // interlace
    w.u(0, 4);   // tfcntrflag, finterpflag, reserved, psf
    w.u(1, 1);   // display_ext
    w.u(1919, 14);
    w.u(1079, 14);
    w.u(1, 1);   // aspect_ratio_flag
    w.u(15, 4);  // aspect_ratio = 15: explicit
    w.u(15, 8);  // aspect_horiz_size - 1 -> 16
    w.u(8, 8);   // aspect_vert_size - 1 -> 9
    w.u(0, 32);
    return w.finish();
}

static void test_vc1()
{
    begin("vc1_advanced_sequence_header");
    {
        Bytes in = {0x00, 0x00, 0x01, 0x0f};
        append(in, vc1_advanced_seqhdr());
        append(in, {0x00, 0x00, 0x01, 0x0e, 0x00, 0x00, 0x00, 0x00}); // entry point
        Bytes buf = padded(in);
        CVC1HeaderParser p(buf.data(), in.size(), AV_CODEC_ID_VC1);
        CHECK_EQ(p.hdr.valid, 1);
        CHECK_EQ(p.hdr.profile, 3);
        CHECK_EQ(p.hdr.level, 3);
        CHECK_EQ(p.hdr.width, 1920);
        CHECK_EQ(p.hdr.height, 1080);
        CHECK_EQ(p.hdr.interlaced, 1);
        CHECK_EQ(p.hdr.ar.num, 16);
        CHECK_EQ(p.hdr.ar.den, 9);
    }
    end();

    begin("wmv3_simple_main_header");
    {
        BitWriter w;
        w.u(1, 2); // profile: main
        w.u(0, 1); // res_y411
        w.u(0, 1); // res_sprite
        w.u(0, 8); // frmrtq/bitrtq
        w.u(0, 11); // loop_filter, res_x8, multires, res_fasttx, fastuvmc, extended_mv, dquant(2), vstransform, res_transtab, overlap
        w.u(0, 1);  // syncmarker
        w.u(1, 1); // rangered
        w.u(5, 3); // maxbframes
        w.u(0, 2); // quantizer
        w.u(1, 1); // finterpflag
        w.u(0, 2);
        Bytes in = w.finish();
        Bytes buf = padded(in);
        CVC1HeaderParser p(buf.data(), in.size(), AV_CODEC_ID_WMV3);
        CHECK_EQ(p.hdr.valid, 1);
        CHECK_EQ(p.hdr.profile, 1);
        CHECK_EQ(p.hdr.rangered, 1);
        CHECK_EQ(p.hdr.bframes, 5);
        CHECK_EQ(p.hdr.finterp, 1);
    }
    end();
}

static void test_audio()
{
    begin("ac3_header");
    {
        // syncword 0B77, crc1, fscod 0 (48 kHz) frmsizecod 28 (448 kbit/s), bsid 8, bsmod 0, acmod 2.
        Bytes frame(1792, 0);
        const uint8_t hdr[] = {0x0b, 0x77, 0x00, 0x00, 0x1c, 0x40, 0x40, 0x00};
        memcpy(frame.data(), hdr, sizeof(hdr));
        Bytes buf = padded(frame);
        CBitstreamParser p;
        HRESULT hr = p.Parse(AV_CODEC_ID_AC3, buf.data(), (DWORD)frame.size());
        CHECK_EQ(hr, S_OK);
        CHECK_EQ(p.m_dwSampleRate, 48000);
        CHECK_EQ(p.m_dwSamples, 1536);
    }
    end();

    begin("ac3_garbage_rejected");
    {
        Bytes frame(64, 0x55);
        Bytes buf = padded(frame);
        CBitstreamParser p;
        CHECK_EQ(p.Parse(AV_CODEC_ID_AC3, buf.data(), (DWORD)frame.size()), E_FAIL);
        CHECK_EQ(p.m_dwSampleRate, 0);
    }
    end();

    begin("dts_core_header");
    {
        BitWriter w;
        w.u(0x7ffe8001, 32);
        w.u(1, 1);    // frame type: normal
        w.u(31, 5);   // samples deficit -> 32 per block
        w.u(0, 1);    // CRC present
        w.u(15, 7);   // blocks - 1 -> 16
        w.u(1005, 14); // frame size - 1 -> 1006
        w.u(9, 6);    // channel arrangement
        w.u(13, 4);   // sample frequency index 13 -> 48000
        w.u(0, 32);
        Bytes frame = w.out;
        frame.resize(1006, 0);
        Bytes buf = padded(frame);
        CBitstreamParser p;
        HRESULT hr = p.Parse(AV_CODEC_ID_DTS, buf.data(), (DWORD)frame.size());
        CHECK_EQ(hr, S_OK);
        CHECK_EQ(p.m_dwSampleRate, 48000);
        CHECK_EQ(p.m_dwBlocks, 16);
        CHECK_EQ(p.m_dwFrameSize, 1006);
        CHECK_EQ(p.m_dwSamples, 512);
        CHECK_EQ(p.m_bDTSHD, 0);
    }
    end();

    begin("truehd_major_sync");
    {
        Bytes frame(32, 0);
        const uint8_t hdr[] = {0x00, 0x00, 0x00, 0x00, 0xf8, 0x72, 0x6f, 0xba, 0x90};
        memcpy(frame.data(), hdr, sizeof(hdr));
        Bytes buf = padded(frame);
        CBitstreamParser p;
        p.Parse(AV_CODEC_ID_TRUEHD, buf.data(), (DWORD)frame.size());
        CHECK_EQ(p.m_dwSampleRate, 88200); // rate bits 1001: 44.1 kHz family, << 1
        CHECK_EQ(p.m_dwSamples, 24 * 80);
    }
    end();
}

static void test_annexb()
{
    begin("annexb_convert_length4");
    {
        Bytes in = {0, 0, 0, 3, 0xaa, 0xbb, 0xcc, 0, 0, 0, 2, 0xdd, 0xee};
        Bytes buf = padded(in);
        CAnnexBConverter c;
        c.SetNALUSize(4);
        BYTE *out = nullptr;
        int out_size = 0;
        HRESULT hr = c.Convert(&out, &out_size, buf.data(), (int)in.size());
        CHECK_EQ(hr, S_OK);
        Bytes expect = {0, 0, 0, 1, 0xaa, 0xbb, 0xcc, 0, 0, 1, 0xdd, 0xee};
        CHECK_EQ(out_size, expect.size());
        CHECK_EQ(out && out_size == (int)expect.size() && memcmp(out, expect.data(), expect.size()) == 0, 1);
        av_freep(&out);
    }
    end();

    begin("annexb_convert_truncated");
    {
        Bytes in = {0, 5, 0xaa, 0xbb}; // 2-byte length 5, only 2 bytes follow
        Bytes buf = padded(in);
        CAnnexBConverter c;
        c.SetNALUSize(2);
        BYTE *out = nullptr;
        int out_size = 0;
        CHECK_EQ(c.Convert(&out, &out_size, buf.data(), (int)in.size()), E_FAIL);
        CHECK_EQ(out == nullptr, 1);
    }
    end();

    begin("annexb_hevc_extradata");
    {
        Bytes in(22, 0);
        in[0] = 1; // configurationVersion
        in.push_back(2); // numOfArrays
        append(in, {0x20, 0x00, 0x01, 0x00, 0x03, 0x40, 0x01, 0x0c});              // VPS array, 1 NAL
        append(in, {0x21, 0x00, 0x02, 0x00, 0x02, 0x42, 0x01, 0x00, 0x01, 0x99}); // SPS array, 2 NALs
        Bytes buf = padded(in);
        CAnnexBConverter c;
        BYTE *out = nullptr;
        int out_size = 0;
        CHECK_EQ(c.ConvertHEVCExtradata(&out, &out_size, buf.data(), (int)in.size()), S_OK);
        Bytes expect = {0, 0, 0, 1, 0x40, 0x01, 0x0c, 0, 0, 1, 0x42, 0x01, 0, 0, 1, 0x99};
        CHECK_EQ(out_size, expect.size());
        CHECK_EQ(out && out_size == (int)expect.size() && memcmp(out, expect.data(), expect.size()) == 0, 1);
        av_freep(&out);
    }
    end();
}

static void test_cuesheet()
{
    begin("cuesheet_tracks");
    {
        const char *text = "REM GENRE Rock\n"
                           "PERFORMER \"The Band\"\n"
                           "TITLE \"Live Album\"\n"
                           "FILE \"album.flac\" WAVE\n"
                           "  TRACK 01 AUDIO\n"
                           "    TITLE \"Opening\"\n"
                           "    INDEX 01 00:00:00\n"
                           "  TRACK 02 AUDIO\n"
                           "    TITLE \"Second Song\"\n"
                           "    PERFORMER \"Guest\"\n"
                           "    INDEX 00 03:58:00\n"
                           "    INDEX 01 04:01:30\n"
                           "  TRACK 03 AUDIO\n"
                           "    INDEX 00 09:00:00\n";
        CCueSheet cue;
        CHECK_EQ(cue.Parse(text), S_OK);
        CHECK_STR(cue.m_Performer, "The Band");
        CHECK_STR(cue.m_Title, "Live Album");
        CHECK_EQ(cue.m_Tracks.size(), 3);
        if (cue.m_Tracks.size() == 3)
        {
            auto it = cue.m_Tracks.begin();
            CCueSheet::Track &t1 = *it++;
            CCueSheet::Track &t2 = *it++;
            CCueSheet::Track &t3 = *it++;
            CHECK_EQ(t1.index, 0);
            CHECK_EQ(t1.Time, 0);
            CHECK_STR(cue.FormatTrack(t1), "01. Opening");
            CHECK_EQ(t2.index, 1);
            // INDEX 01 wins over INDEX 00: 4 min 1 s + 30/75 s, in 100 ns units.
            CHECK_EQ(t2.Time, (4LL * 60 + 1) * 10000000LL + 30 * 10000000LL / 75);
            CHECK_STR(cue.FormatTrack(t2), "02. Guest - Second Song");
            // no INDEX 01: falls back to INDEX 00; no TITLE: default title.
            CHECK_EQ(t3.Time, 9LL * 60 * 10000000LL);
            CHECK_STR(cue.FormatTrack(t3), "03. Title 03");
        }
    }
    end();

    begin("cuesheet_multiple_files_rejected");
    {
        CCueSheet cue;
        CHECK_EQ(cue.Parse("FILE \"a.wav\" WAVE\nTRACK 01 AUDIO\nFILE \"b.wav\" WAVE\n"), E_FAIL);
    }
    end();
}

int main()
{
    test_h264();
    test_hevc();
    test_mpeg2();
    test_extradata();
    test_vc1();
    test_audio();
    test_annexb();
    test_cuesheet();
    printf("SUMMARY passed=%d failed=%d\n", g_passed, g_failed);
    return g_failed ? 1 : 0;
}

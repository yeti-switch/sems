#include "amci/amci.h"
#include "amci/codecs.h"
#include "log.h"

#include <stdio.h>
#include <opencore-amrnb/interf_enc.h>
#include <opencore-amrnb/interf_dec.h>
#include <vo-amrwbenc/enc_if.h>
#include <opencore-amrwb/dec_if.h>

#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* speech bits by frame type: 3GPP TS 26.101 (AMR), TS 26.201 (AMR-WB); -1: not supported */
static const int amr_bits[16]   = { 95, 103, 118, 134, 148, 159, 204, 244, 39, -1, -1, -1, -1, -1, -1, 0 };
static const int amrwb_bits[16] = { 132, 177, 253, 285, 317, 365, 397, 461, 477, 40, -1, -1, -1, -1, 0, 0 };

typedef enum {
    AMR_OPT_OCTET_ALIGN          = (1 << 0),
    AMR_OPT_CRC                  = (1 << 1),
    AMR_OPT_MODE_CHANGE_NEIGHBOR = (1 << 2),
    AMR_OPT_ROBUST_SORTING       = (1 << 3),
    AMR_OPT_INTERLEAVING         = (1 << 4)
} amr_flag_t;

typedef enum {
    GENERIC_PARAMETER_AMR_MAXAL_SDUFRAMES = 0,
    GENERIC_PARAMETER_AMR_BITRATE,
    GENERIC_PARAMETER_AMR_GSMAMRCOMFORTNOISE,
    GENERIC_PARAMETER_AMR_GSMEFRCOMFORTNOISE,
    GENERIC_PARAMETER_AMR_IS_641COMFORTNOISE,
    GENERIC_PARAMETER_AMR_PDCEFRCOMFORTNOISE
} amr_param_t;

typedef enum {
    AMR_BITRATE_475 = 0,
    AMR_BITRATE_515,
    AMR_BITRATE_590,
    AMR_BITRATE_670,
    AMR_BITRATE_740,
    AMR_BITRATE_795,
    AMR_BITRATE_1020,
    AMR_BITRATE_1220
} amr_bitrate_t;

typedef enum { AMR_DTX_DISABLED = 0, AMR_DTX_ENABLED } amr_dtx_t;

static int pcm16_2_amr(unsigned char *out_buf, unsigned char *in_buf, unsigned int size, unsigned int channels,
                       unsigned int rate, long h_codec);
static int pcm16_2_amrwb(unsigned char *out_buf, unsigned char *in_buf, unsigned int size, unsigned int channels,
                         unsigned int rate, long h_codec);

static int amr_2_pcm16(unsigned char *out_buf, unsigned char *in_buf, unsigned int size, unsigned int channels,
                       unsigned int rate, long h_codec);
static int amrwb_2_pcm16(unsigned char *out_buf, unsigned char *in_buf, unsigned int size, unsigned int channels,
                         unsigned int rate, long h_codec);


static long amr_create(const char *format_parameters, amci_codec_fmt_info_t *format_description);
static long amrwb_create(const char *format_parameters, amci_codec_fmt_info_t *format_description);
static void amr_destroy(long h_codec);
static void amrwb_destroy(long h_codec);

static unsigned int amr_bytes2samples(long, unsigned int);
static unsigned int amr_samples2bytes(long, unsigned int);
// static unsigned int amr_frames2samples(long, unsigned char *,unsigned int);

static unsigned int amrwb_bytes2samples(long, unsigned int);
static unsigned int amrwb_samples2bytes(long, unsigned int);
// static unsigned int amrwb_frames2samples(long, unsigned char *,unsigned int);


#define AMR_PAYLOAD_ID   118
#define AMRWB_PAYLOAD_ID 119

#define AMR_BYTES_PER_FRAME   10
#define AMR_SAMPLES_PER_FRAME 160

#define AMRWB_BYTES_PER_FRAME   10
#define AMRWB_SAMPLES_PER_FRAME 320

#define AMRWB_DEFAULT_MODE 7 /* 23.05 kbit/s */
#define AMRWB_MAX_MODE     8

#define AMR_FT_NO_DATA    15
#define AMR_MAX_FRAMES    12 /* maxptime 240 ms */
#define AMR_MAX_FRAME_LEN 62 /* header + AMR-WB 23.85 kbit/s */

#define OCTET_ALIGN(pos) (((pos) + 7) & ~7u)

#ifndef TEST

BEGIN_EXPORTS("amr", AMCI_NO_MODULEINIT, AMCI_NO_MODULEDESTROY)

BEGIN_CODECS
CODEC /*_VARIABLE_FRAMES*/ (CODEC_AMR, pcm16_2_amr, amr_2_pcm16, AMCI_NO_CODEC_PLC, (amci_codec_init_t)amr_create,
                            (amci_codec_destroy_t)amr_destroy, amr_bytes2samples,
                            amr_samples2bytes //, amr_frames2samples
                            ) CODEC
    /*_VARIABLE_FRAMES*/ (CODEC_AMRWB, pcm16_2_amrwb, amrwb_2_pcm16, AMCI_NO_CODEC_PLC, (amci_codec_init_t)amrwb_create,
                          (amci_codec_destroy_t)amrwb_destroy, amrwb_bytes2samples,
                          amrwb_samples2bytes //, amrwb_frames2samples
                          ) END_CODECS

    BEGIN_PAYLOADS PAYLOAD(AMR_PAYLOAD_ID, "AMR", 8000, 8000, 1, CODEC_AMR, AMCI_PT_AUDIO_FRAME)
        PAYLOAD(AMRWB_PAYLOAD_ID, "AMR-WB", 16000, 16000, 1, CODEC_AMRWB, AMCI_PT_AUDIO_FRAME) END_PAYLOADS

    BEGIN_FILE_FORMATS END_FILE_FORMATS

    END_EXPORTS

#endif

    typedef struct amr_codec {
    void *encoder;
    void *decoder;
    int   octet_align;
    int   enc_mode;
} amr_codec_t;

/* copy nbits from bit offset spos of src to bit offset dpos of dst, MSB first */
static void copy_bits(unsigned char *dst, unsigned dpos, const unsigned char *src, unsigned spos, unsigned nbits)
{
    for (; nbits; nbits--, dpos++, spos++) {
        unsigned char mask = 0x80 >> (dpos & 7);
        if (src[spos >> 3] & (0x80 >> (spos & 7)))
            dst[dpos >> 3] |= mask;
        else
            dst[dpos >> 3] &= ~mask;
    }
}

/* value of the fmtp parameter or NULL */
static const char *fmtp_param(const char *fmtp, const char *name)
{
    size_t len = strlen(name);

    while (fmtp && *fmtp) {
        while (*fmtp == ' ' || *fmtp == ';')
            fmtp++;
        if (!strncasecmp(fmtp, name, len) && fmtp[len] == '=')
            return fmtp + len + 1;
        fmtp = strchr(fmtp, ';');
    }

    return NULL;
}

static void amr_parse_fmtp(struct amr_codec *codec, const char *fmtp, int max_mode)
{
    const char *v;

    /* RFC 4867: bandwidth-efficient unless octet-align=1 */
    v                  = fmtp_param(fmtp, "octet-align");
    codec->octet_align = v && atoi(v) == 1;

    /* restricted mode-set: encode with the highest allowed mode */
    if ((v = fmtp_param(fmtp, "mode-set"))) {
        int best = -1;
        while (*v >= '0' && *v <= '9') {
            char *end;
            int   mode = (int)strtol(v, &end, 10);
            if (mode <= max_mode && mode > best)
                best = mode;
            v = (*end == ',') ? end + 1 : end;
        }
        if (best >= 0)
            codec->enc_mode = best;
    }
}

/* a packet carries whole 20 ms frames */
static void amr_fix_frame_length(amci_codec_fmt_info_t *format_description, int frame_samples)
{
    int nframes = format_description[0].value / 20;

    if (nframes < 1)
        nframes = 1;
    if (nframes > AMR_MAX_FRAMES)
        nframes = AMR_MAX_FRAMES;

    format_description[0].value = nframes * 20;
    format_description[1].value = nframes * frame_samples;
}

long amr_create(const char *format_parameters, amci_codec_fmt_info_t *format_description)
{
    struct amr_codec *codec;

    DBG("amr_create: AMR format parameters: [%s], format description: [id=%d, val=%d]\n", format_parameters,
        format_description->id, format_description->value);

    codec = (struct amr_codec *)malloc(sizeof(struct amr_codec));
    if (!codec) {
        ERROR("amr.c: could not create handle array\n");
        return 0;
    }

    codec->enc_mode = MR122;
    amr_parse_fmtp(codec, format_parameters, MR122);
    amr_fix_frame_length(format_description, AMR_SAMPLES_PER_FRAME);

    codec->encoder = Encoder_Interface_init(0 /*codec->dtx_mode*/);
    codec->decoder = Decoder_Interface_init();

    return (long)codec;
}


long amrwb_create(const char *format_parameters, amci_codec_fmt_info_t *format_description)
{
    struct amr_codec *codec;

    DBG("amr_create: AMR format parameters: [%s], format description: [id=%d, val=%d]\n", format_parameters,
        format_description->id, format_description->value);

    codec = (struct amr_codec *)malloc(sizeof(struct amr_codec));
    if (!codec) {
        ERROR("amr.c: could not create handle array\n");
        return 0;
    }

    codec->enc_mode = AMRWB_DEFAULT_MODE;
    amr_parse_fmtp(codec, format_parameters, AMRWB_MAX_MODE);
    amr_fix_frame_length(format_description, AMRWB_SAMPLES_PER_FRAME);

    codec->encoder = E_IF_init();
    codec->decoder = D_IF_init();

    return (long)codec;
}

static void amr_destroy(long h_codec)
{
    struct amr_codec *codec = (struct amr_codec *)h_codec;

    if (!h_codec)
        return;

    Encoder_Interface_exit(codec->encoder);
    Decoder_Interface_exit(codec->decoder);

    free(codec);
}

static void amrwb_destroy(long h_codec)
{
    struct amr_codec *codec = (struct amr_codec *)h_codec;

    if (!h_codec)
        return;

    E_IF_exit(codec->encoder);
    D_IF_exit(codec->decoder);

    free(codec);
}

/* RFC 4867 payload: CMR, table of contents, speech frames */
static int amr_encode(unsigned char *out_buf, unsigned char *in_buf, unsigned int size, long h_codec, int wb)
{
    struct amr_codec *codec      = (struct amr_codec *)h_codec;
    const int        *frame_bits = wb ? amrwb_bits : amr_bits;
    unsigned int      frame_size = 2 * (wb ? AMRWB_SAMPLES_PER_FRAME : AMR_SAMPLES_PER_FRAME);
    unsigned int      nframes    = size / frame_size, pos, i;
    unsigned char     frames[AMR_MAX_FRAMES][AMR_MAX_FRAME_LEN];

    if (!h_codec) {
        ERROR("Codec not initialized (h_codec = %li)?!?\n", h_codec);
        return -1;
    }

    if (!nframes || nframes > AMR_MAX_FRAMES)
        return -1;

    /* encoder output: (FT << 3) | (Q << 2), then speech bits */
    for (i = 0; i < nframes; i++) {
        const short *pcm = (const short *)(in_buf + i * frame_size);
        if (wb)
            E_IF_encode(codec->encoder, codec->enc_mode, pcm, frames[i], 0);
        else
            Encoder_Interface_Encode(codec->encoder, (enum Mode)codec->enc_mode, pcm, frames[i], 0);
    }

    memset(out_buf, 0, 1 + nframes * AMR_MAX_FRAME_LEN);

    /* CMR 15: no mode request */
    out_buf[0] = 0xf0;
    pos        = codec->octet_align ? 8 : 4;

    for (i = 0; i < nframes; i++) {
        unsigned char toc = (frames[i][0] & 0x7c) | (i + 1 < nframes ? 0x80 : 0);
        copy_bits(out_buf, pos, &toc, 0, 6);
        pos += codec->octet_align ? 8 : 6;
    }

    for (i = 0; i < nframes; i++) {
        int bits = frame_bits[(frames[i][0] >> 3) & 0x0f];
        if (bits < 0)
            return -1;
        copy_bits(out_buf, pos, frames[i] + 1, 0, bits);
        pos += bits;
        if (codec->octet_align)
            pos = OCTET_ALIGN(pos);
    }

    return (pos + 7) / 8;
}

static int amr_decode(unsigned char *out_buf, unsigned char *in_buf, unsigned int size, long h_codec, int wb)
{
    struct amr_codec *codec         = (struct amr_codec *)h_codec;
    const int        *frame_bits    = wb ? amrwb_bits : amr_bits;
    unsigned int      frame_samples = wb ? AMRWB_SAMPLES_PER_FRAME : AMR_SAMPLES_PER_FRAME;
    unsigned int      total = size * 8, pos, nframes = 0, i;
    unsigned char     toc[AMR_MAX_FRAMES], frame[AMR_MAX_FRAME_LEN];
    short            *dst = (short *)out_buf;

    if (!h_codec) {
        ERROR("Codec not initialized (h_codec = %li)?!?\n", h_codec);
        return -1;
    }

    /* skip CMR */
    pos = codec->octet_align ? 8 : 4;

    do {
        if (nframes == AMR_MAX_FRAMES || pos + 6 > total)
            return 0;
        toc[nframes] = 0;
        copy_bits(&toc[nframes], 0, in_buf, pos, 6);
        pos += codec->octet_align ? 8 : 6;
    } while (toc[nframes++] & 0x80);

    for (i = 0; i < nframes; i++) {
        int bits = frame_bits[(toc[i] >> 3) & 0x0f];

        /* unsupported frame type or truncated packet */
        if (bits < 0 || pos + bits > total)
            break;

        memset(frame, 0, sizeof(frame));
        /* damaged frame (Q=0) is concealed as NO_DATA */
        frame[0] = (toc[i] & 0x04) ? (toc[i] & 0x7c) : (AMR_FT_NO_DATA << 3);
        copy_bits(frame + 1, 0, in_buf, pos, bits);
        pos += bits;
        if (codec->octet_align)
            pos = OCTET_ALIGN(pos);

        if (wb)
            D_IF_decode(codec->decoder, frame, dst + i * frame_samples, 0);
        else
            Decoder_Interface_Decode(codec->decoder, frame, dst + i * frame_samples, 0);
    }

    return 2 * i * frame_samples;
}

static int pcm16_2_amr(unsigned char *out_buf, unsigned char *in_buf, unsigned int size, unsigned int channels,
                       unsigned int rate, long h_codec)
{
    return amr_encode(out_buf, in_buf, size, h_codec, 0);
}

static int amr_2_pcm16(unsigned char *out_buf, unsigned char *in_buf, unsigned int size, unsigned int channels,
                       unsigned int rate, long h_codec)
{
    return amr_decode(out_buf, in_buf, size, h_codec, 0);
}

static int pcm16_2_amrwb(unsigned char *out_buf, unsigned char *in_buf, unsigned int size, unsigned int channels,
                         unsigned int rate, long h_codec)
{
    return amr_encode(out_buf, in_buf, size, h_codec, 1);
}

static int amrwb_2_pcm16(unsigned char *out_buf, unsigned char *in_buf, unsigned int size, unsigned int channels,
                         unsigned int rate, long h_codec)
{
    return amr_decode(out_buf, in_buf, size, h_codec, 1);
}

static unsigned int amr_bytes2samples(long h_codec, unsigned int num_bytes)
{
    return (AMR_SAMPLES_PER_FRAME * num_bytes) / AMR_BYTES_PER_FRAME;
}

static unsigned int amr_samples2bytes(long h_codec, unsigned int num_samples)
{
    return AMR_BYTES_PER_FRAME * num_samples / AMR_SAMPLES_PER_FRAME;
}
/*
static unsigned int amr_frames2samples(long h_codec, unsigned char *in,unsigned int size)
{
    return
}*/

static unsigned int amrwb_bytes2samples(long h_codec, unsigned int num_bytes)
{
    return (AMRWB_SAMPLES_PER_FRAME * num_bytes) / AMRWB_BYTES_PER_FRAME;
}

static unsigned int amrwb_samples2bytes(long h_codec, unsigned int num_samples)
{
    return AMRWB_BYTES_PER_FRAME * num_samples / AMRWB_SAMPLES_PER_FRAME;
}
/*
static unsigned int amrwb_frames2samples(long h_codec, unsigned char *in,unsigned int size)
{
}*/

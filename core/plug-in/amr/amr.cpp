#include "amci/amci.h"
#include "amci/codecs.h"
#include "log.h"

#include <stdio.h>
#include <opencore-amrnb/interf_enc.h>
#include <opencore-amrnb/interf_dec.h>
#include <vo-amrwbenc/enc_if.h>
#include <opencore-amrwb/dec_if.h>

#include <stdlib.h>
#include <assert.h>

/* Taken from Table 2, of 3GPP TS 26.101, v5.0.0 */
/* Taken from Table 3, of 3GPP TS 26.101, v5.0.0: Comfort Noise (FT 8) */
static int num_bits[16] = { 95, 103, 118, 134, 148, 159, 204, 244, 39 };

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

} amr_codec_t;

/* Pack bits into dst, advance ptr */
static int pack_bits(unsigned char **dst, int d_offset, const unsigned char *src, unsigned sbits)
{
    unsigned char       *p = *dst;
    unsigned             s_offset, x, y, sbytes = (sbits + 7) / 8; /* Number of bytes. */
    const unsigned char *end_ptr = src + sbytes;

    assert(d_offset >= 0 && d_offset < 8);
    //    DBG("pack_bits: off=%d,sbits=%d\n", d_offset, sbits);

    /* Fill first dst byte, then we proceed */
    x = d_offset + 1;
    /* *p &= (1<<x) - 1; Clear top bits. */

    *p = (*p & (~0 << x)) | (*src >> (8 - x)); /* Clear bits, then set */
    if (d_offset == 7)
        src++;
    /* Now fill whole dst bytes in each pass */
    s_offset = (d_offset == 7) ? 7 : 7 - x;
    y        = s_offset + 1;
    while (src < end_ptr) {
        p++; /* Go to next; Only do so here, because we need to go to next only if octet is used up. */
        *p = (*src & ((1 << y) - 1)) << (8 - y);
        if (s_offset < 7) /* Need part of next byte. Redundant check? I think so */
            *p |= (src[1] >> y) & ((1 << (8 - s_offset)) - 1);
        src++;
    }

    if (*dst == p && (sbits % 8) == 0)
        p++; /* Terrible kludge, but... */

    *dst = p;

    /* Compute new d_offset */
    if (sbits > x) {
        sbits = (sbits - x) % 8; /* We'd have filled in first byte, and X full bytes */

        /* We now have a remainder set of bits, which are fewer than 8, time to fill them in and calculate */
        d_offset = 7 - sbits;
    } else {
        d_offset -= sbits; /* We stayed in same byte, or just filled it: Subtract # of bits added */
        if (d_offset < 0)
            d_offset = 7;
    }
    return d_offset;
}

/* unpack bits from src, advance src */
static int unpack_bits(unsigned char **src, int s_offset, unsigned char *dst, unsigned sbits)
{

    unsigned char *q = *src;
    ;

    assert(s_offset >= 0 && s_offset <= 7);
    while (sbits > 0) {
        int      bits = sbits >= 8 ? 8 : sbits;
        unsigned mask = ~((1 << (8 - bits)) - 1);
        int      x    = s_offset + 1;

        *dst = (*q << (8 - x));                                     /* Set */
        if (x - bits < 0)                                           /* Get bit off next byte */
            *dst |= (q[1] >> x) /*  & ((1 << (8-s_offset)) - 1) */; /* right shift of unsigned left pads with zeros*/

        *dst &= mask; /* Clear all other bits */

        s_offset -= bits;
        if (s_offset < 0) { /* This means we got a bit off next byte or all of current byte, so move. */
            q++;
            s_offset += 8;
        }
        dst++;
        sbits -= bits;
    }

    *src = q;

    return s_offset;
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

static int pcm16_2_amr(unsigned char *out_buf, unsigned char *in_buf, unsigned int size, unsigned int channels,
                       unsigned int rate, long h_codec)
{

    struct amr_codec   *codec = (struct amr_codec *)h_codec;
    unsigned char       cmr, *phdr, *pdata, toc_entry;
    unsigned char       sbuffer[1024];
    unsigned int        d_offset, h_offset, mode, q, bits;
    int                 pbits = 0, sbits = 0, len, npad;
    const unsigned char xzero         = 0;
    int                 octed_aligned = 1;

    if (!h_codec) {
        ERROR("Codec not initialized (h_codec = %li)?!?\n", h_codec);
        return -1;
    }

    phdr  = out_buf;
    pdata = sbuffer;

    cmr = 7;
    cmr <<= 4;
    h_offset = d_offset = 7;
    h_offset            = pack_bits(&phdr, h_offset, &cmr, octed_aligned ? 8 : 4);
    pbits += octed_aligned ? 8 : 4;

    len = Encoder_Interface_Encode(codec->encoder, /*context->enc_mode*/ MR122, (int16_t *)in_buf, sbuffer, 0);
    //   DBG("Encoder_Interface_Encode returned %i\n", len);

    mode      = (sbuffer[0] >> 3) & 0x0F;
    q         = (sbuffer[0] >> 2) & 0x01;
    toc_entry = (mode << 3) | (q << 2);
    bits      = octed_aligned ? (num_bits[mode] + 7) & ~7 : num_bits[mode];

    h_offset =
        pack_bits(&phdr, h_offset, &toc_entry, octed_aligned ? 8 : 6); /* put in the table of contents element. */

    pbits += octed_aligned ? 8 : 6;
    /* Pack the bits of the speech. */
    d_offset = pack_bits(&pdata, d_offset, &sbuffer[1], bits);
    sbits += bits;

    /* CMR+TOC  is already in outbuf. So: Add speech bits */
    h_offset = pack_bits(&phdr, h_offset, sbuffer /*tmp->speech_bits*/, sbits);
    npad     = (8 - ((sbits + pbits) & 7)) & 0x7; /* Number of padding bits */

    if (octed_aligned && npad != 0)
        ERROR("Padding bits cannot be > 0 in octet aligned mode!\n");

    pack_bits(&phdr, h_offset, &xzero, npad); /* zero out the rest of the padding bits. */
    len = (sbits + pbits + npad + 7) / 8;     /* Round up to nearest octet. */
    //   DBG("(sbits %i + pbits %i + npad %i + 7) / 8 = %i\n", sbits, pbits, npad, len);

    return len; // out_size;
}

/* DECODE */
static int amr_2_pcm16(unsigned char *out_buf, unsigned char *in_buf, unsigned int size, unsigned int channels,
                       unsigned int rate, long h_codec)
{
    /* div_t blocks; */
    int               datalen = 0;
    int               x, nframes = 0;
    struct amr_codec *codec         = (struct amr_codec *)h_codec;
    unsigned char    *src           = in_buf;
    unsigned char     more_frames   = 1, cmr, buffer[1024], type, ch; // AMR_MAX_FRAME_LEN+1
    int16_t          *dst           = (int16_t *)out_buf;
    int               octed_aligned = 1;

    struct {
        unsigned char ft;
        unsigned char q;
    } toc[50]{}; //(BUFFER_SAMPLES*1000)/(SAMPLES_PER_SEC_NB*20) 8000*1000/8000*20


    if (!h_codec) {
        ERROR("Codec not initialized (h_codec = %li)?!?\n", h_codec);
        return -1;
    }

    unsigned char *end_ptr = in_buf + size;
    int            pos     = unpack_bits(&src, 7, &cmr, octed_aligned ? 8 : 4);

    //    DBG("cmr = %x (%u)\n", cmr, cmr);

    /* Get the table of contents first... */
    while (src < end_ptr && more_frames) {
        type = src[0] & 0x3e;
        //	DBG("type & 0x3e = %x (%u)\n", type, type);
        /* More-Frames Indicator: */
        pos = unpack_bits(&src, pos, &more_frames, 1);
        pos = unpack_bits(&src, pos, &toc[nframes].ft, 4);
        pos = unpack_bits(&src, pos, &toc[nframes].q, 1);
        if (octed_aligned)
            pos = unpack_bits(&src, pos, &ch, 2);

        toc[nframes].ft >>= 4;
        toc[nframes].q >>= 7;

        //	DBG("=============== FRAME %i ===============\n", nframes);
        //	DBG("pos = %i\n", pos);
        //	DBG("more_frames = %i\n", more_frames);
        //	DBG("ft = %u\n", toc[nframes].ft);
        //	DBG("q = %u\n", toc[nframes].q);
        nframes++;
    }

    /* Now get the speech bits, and decode as we go. */
    int samples = 0, bits;

    for (x = 0; x < nframes; x++) {
        unsigned char ft = toc[x].ft; // , q = toc[x].q;
        if (ft > 7)                   /* No data or invalid */
            goto loop;

        bits = octed_aligned ? (num_bits[ft] + 7) & ~7 : num_bits[ft];

        /* for octet-aligned mode, the speech frames are octet aligned as well */
        pos       = unpack_bits(&src, pos, &buffer[1], bits);
        buffer[0] = type; // (ft << 1) | (q << 5);

        Decoder_Interface_Decode(codec->decoder, buffer, dst + samples, 0);

        samples += AMR_SAMPLES_PER_FRAME;
        datalen += 2 * AMR_SAMPLES_PER_FRAME;

    loop:
        (void)0;
    }

    //  DBG("datalen = %i\n", datalen);

    return datalen;
}


static int pcm16_2_amrwb(unsigned char *out_buf, unsigned char *in_buf, unsigned int size, unsigned int channels,
                         unsigned int rate, long h_codec)
{

    struct amr_codec   *codec = (struct amr_codec *)h_codec;
    unsigned char       cmr, *phdr, *pdata, toc_entry;
    unsigned char       sbuffer[1024];
    unsigned int        d_offset, h_offset, mode, q, bits;
    int                 pbits = 0, sbits = 0, len, npad;
    const unsigned char xzero         = 0;
    int                 octed_aligned = 1;

    if (!h_codec) {
        ERROR("Codec not initialized (h_codec = %li)?!?\n", h_codec);
        return -1;
    }

    phdr  = out_buf;
    pdata = sbuffer;

    cmr = 7;
    cmr <<= 4;
    h_offset = d_offset = 7;
    h_offset            = pack_bits(&phdr, h_offset, &cmr, octed_aligned ? 8 : 4);
    pbits += octed_aligned ? 8 : 4;

    len = E_IF_encode(codec->encoder, /*context->enc_mode*/ 7, (int16_t *)in_buf, sbuffer, 0);
    //   DBG("Encoder_Interface_Encode returned %i\n", len);

    mode      = (sbuffer[0] >> 3) & 0x0F;
    q         = (sbuffer[0] >> 2) & 0x01;
    toc_entry = (mode << 3) | (q << 2);
    bits      = octed_aligned ? (num_bits[mode] + 7) & ~7 : num_bits[mode];

    h_offset =
        pack_bits(&phdr, h_offset, &toc_entry, octed_aligned ? 8 : 6); /* put in the table of contents element. */

    pbits += octed_aligned ? 8 : 6;
    /* Pack the bits of the speech. */
    d_offset = pack_bits(&pdata, d_offset, &sbuffer[1], bits);
    sbits += bits;

    /* CMR+TOC  is already in outbuf. So: Add speech bits */
    h_offset = pack_bits(&phdr, h_offset, sbuffer /*tmp->speech_bits*/, sbits);
    npad     = (8 - ((sbits + pbits) & 7)) & 0x7; /* Number of padding bits */

    if (octed_aligned && npad != 0)
        ERROR("Padding bits cannot be > 0 in octet aligned mode!\n");

    pack_bits(&phdr, h_offset, &xzero, npad); /* zero out the rest of the padding bits. */
    len = (sbits + pbits + npad + 7) / 8;     /* Round up to nearest octet. */
    //   DBG("(sbits %i + pbits %i + npad %i + 7) / 8 = %i\n", sbits, pbits, npad, len);

    return len; // out_size;
}

/* DECODE */
static int amrwb_2_pcm16(unsigned char *out_buf, unsigned char *in_buf, unsigned int size, unsigned int channels,
                         unsigned int rate, long h_codec)
{
    /* div_t blocks; */
    int               datalen = 0;
    int               x, nframes = 0;
    struct amr_codec *codec         = (struct amr_codec *)h_codec;
    unsigned char    *src           = in_buf;
    unsigned char     more_frames   = 1, cmr, buffer[1024], type, ch; // AMR_MAX_FRAME_LEN+1
    int16_t          *dst           = (int16_t *)out_buf;
    int               octed_aligned = 1;

    struct {
        unsigned char ft;
        unsigned char q;
    } toc[50]{}; //(BUFFER_SAMPLES*1000)/(SAMPLES_PER_SEC_NB*20) 8000*1000/8000*20


    if (!h_codec) {
        ERROR("Codec not initialized (h_codec = %li)?!?\n", h_codec);
        return -1;
    }

    unsigned char *end_ptr = in_buf + size;
    int            pos     = unpack_bits(&src, 7, &cmr, octed_aligned ? 8 : 4);

    //   DBG("cmr = %x (%u)\n", cmr, cmr);

    /* Get the table of contents first... */
    while (src < end_ptr && more_frames) {
        type = src[0] & 0x3e;
        //	DBG("type & 0x3e = %x (%u)\n", type, type);
        /* More-Frames Indicator: */
        pos = unpack_bits(&src, pos, &more_frames, 1);
        pos = unpack_bits(&src, pos, &toc[nframes].ft, 4);
        pos = unpack_bits(&src, pos, &toc[nframes].q, 1);
        if (octed_aligned)
            pos = unpack_bits(&src, pos, &ch, 2);

        toc[nframes].ft >>= 4;
        toc[nframes].q >>= 7;

        //	DBG("=============== FRAME %i ===============\n", nframes);
        //	DBG("pos = %i\n", pos);
        //	DBG("more_frames = %i\n", more_frames);
        //	DBG("ft = %u\n", toc[nframes].ft);
        //	DBG("q = %u\n", toc[nframes].q);
        nframes++;
    }

    /* Now get the speech bits, and decode as we go. */
    int samples = 0, bits;
    for (x = 0; x < nframes; x++) {
        unsigned char ft = toc[x].ft; // , q = toc[x].q;
        if (ft > 7)                   /* No data or invalid */
            goto loop;

        bits = octed_aligned ? (num_bits[ft] + 7) & ~7 : num_bits[ft];

        /* for octet-aligned mode, the speech frames are octet aligned as well */
        pos       = unpack_bits(&src, pos, &buffer[1], bits);
        buffer[0] = type; // (ft << 1) | (q << 5);

        D_IF_decode(codec->decoder, buffer, dst + samples, 0);

        samples += AMRWB_SAMPLES_PER_FRAME;
        datalen += 2 * AMRWB_SAMPLES_PER_FRAME;

    loop:
        (void)0;
    }

    //   DBG("datalen = %i\n", datalen);

    return datalen;
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

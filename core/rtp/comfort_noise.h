/*
 * RTP Payload for Comfort Noise (RFC 3389)
 */

#ifndef _comfort_noise_h_
#define _comfort_noise_h_

#include <sys/types.h>

typedef unsigned char u_int8;

typedef struct {

#if (defined(__BYTE_ORDER) && (__BYTE_ORDER == __BIG_ENDIAN))
    u_int8 r     : 1;
    u_int8 level : 7;
#else
    u_int8 level : 7;
    u_int8 r     : 1;
#endif

    u_int8 spectral[];

} cn_payload_t;

#endif

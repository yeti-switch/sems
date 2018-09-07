#pragma once

#include <stdint.h>
#include <netinet/in.h>

#pragma pack(1)

/**
 * RTCP common header.
 */
struct RtcpCommonHeader
{
    typedef enum {
        RTCP_SR   = 200,
        RTCP_RR   = 201,
        RTCP_SDES = 202,
        RTCP_BYE  = 203,
        RTCP_APP  = 204
    } rtcp_type_t;

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    unsigned    version:2;  /**< packet type            */
    unsigned    p:1;        /**< padding flag           */
    unsigned    count:5;    /**< varies by payload type */
    unsigned    pt:8;       /**< payload type           */
#else
    unsigned    count:5;    /**< varies by payload type */
    unsigned    p:1;        /**< padding flag           */
    unsigned    version:2;  /**< packet type            */
    unsigned    pt:8;       /**< payload type           */
#endif
    unsigned    length:16;  /**< packet length          */
    uint32_t    ssrc;       /**< SSRC identification    */
};

struct RtcpSenderReportHeader
{
    uint32_t    ntp_sec;        /**< NTP time, seconds part.    */
    uint32_t    ntp_frac;       /**< NTP time, fractions part.  */
    uint32_t    rtp_ts;         /**< RTP timestamp.             */
    uint32_t    sender_pcount;  /**< Sender packet count.       */
    uint32_t    sender_bcount;  /**< Sender octet/bytes count.  */
};

struct RtcpReceiverReportHeader
{
    uint32_t    ssrc;           /**< SSRC identification.   */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint32_t    fract_lost:8;   /**< Fraction lost.         */
    uint32_t    total_lost_2:8; /**< Total lost, bit 16-23. */
    uint32_t    total_lost_1:8; /**< Total lost, bit 8-15.  */
    uint32_t    total_lost_0:8; /**< Total lost, bit 0-7.   */
#else
    uint32_t    fract_lost:8;   /**< Fraction lost.         */
    uint32_t    total_lost_2:8; /**< Total lost, bit 0-7.   */
    uint32_t    total_lost_1:8; /**< Total lost, bit 8-15.  */
    uint32_t    total_lost_0:8; /**< Total lost, bit 16-23. */
#endif
    uint32_t    last_seq;       /**< Last sequence number.  */
    uint32_t    jitter;         /**< Jitter.                */
    uint32_t    lsr;            /**< Last SR.               */
    uint32_t    dlsr;           /**< Delay since last SR.   */
};

struct RtcpSourceDescriptionHeader
{
    enum item_type {
        RTCP_SDES_NULL  = 0,
        RTCP_SDES_CNAME = 1,
        RTCP_SDES_NAME  = 2,
        RTCP_SDES_EMAIL = 3,
        RTCP_SDES_PHONE = 4,
        RTCP_SDES_LOC   = 5,
        RTCP_SDES_TOOL  = 6,
        RTCP_SDES_NOTE  = 7
    };
};

#pragma pack()

class RtcpPacket {
    struct sockaddr_storage addr;
};


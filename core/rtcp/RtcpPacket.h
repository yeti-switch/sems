#pragma once

#include "RtcpStat.h"

#include <netinet/in.h>
#include <srtp/srtp.h>

// srtcp data size injected after rtcp packet
// see rfc 3711 sec 3.4
// 4 bt - index
// we are not using mki
// and 16 bt max auth tag see srtp.h SRTP_MAX_TAG_LEN
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
    uint8_t type;
    uint8_t len;
};

struct RtcpSdesData {
    RtcpCommonHeader header;
    RtcpSourceDescriptionHeader item;
    /* 46 requires 1 byte padding (8 + 46 + 1 END item byte + 1 pad byte)
     * https://www.rfc-editor.org/rfc/rfc3550#section-6.5 */
    unsigned char data[INET6_ADDRSTRLEN + 1];
    unsigned int packet_length;
};

struct RtcpSenderReportDataFull {
    struct {
        RtcpCommonHeader header;
        RtcpSenderReportHeader sender;
        RtcpReceiverReportHeader receiver;
    } sr;
    RtcpSdesData sdes;
    unsigned int packet_length;
};

struct RtcpSenderReportDataNoReceiver {
    struct {
        RtcpCommonHeader header;
        RtcpSenderReportHeader sender;
    } sr;
    RtcpSdesData sdes;
    unsigned int packet_length;
};

struct RtcpReceiverReportDataFull {
    struct {
        RtcpCommonHeader header;
        RtcpReceiverReportHeader receiver;
    } rr;
    RtcpSdesData sdes;
    unsigned int packet_length;
};

struct RtcpEmptyReceiverReport {
    struct {
        RtcpCommonHeader header;
    } rr;
    RtcpSdesData sdes;
    unsigned int packet_length;
};

struct RtcpReportsPreparedData {
    RtcpEmptyReceiverReport rr_empty;           //no report blocks
    RtcpSenderReportDataNoReceiver sr_empty;    //no report blocks
    RtcpReceiverReportDataFull rr;
    RtcpSenderReportDataFull sr;

    void init(unsigned int l_ssrc, const string& cname);
    void update(unsigned int r_ssrc);
};

#pragma pack()

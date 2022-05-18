/*
 * Copyright (C) 2002-2003 Fhg Fokus
 *
 * This file is part of SEMS, a free SIP media server.
 *
 * SEMS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version. This program is released under
 * the GPL with the additional exemption that compiling, linking,
 * and/or using OpenSSL is allowed.
 *
 * For a license to use the SEMS software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * SEMS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define __APPLE_USE_RFC_3542
#include <netinet/in.h>

#include "AmRtpPacket.h"
#include "rtcp/RtcpPacket.h"
#include "rtp/rtp.h"
#include "log.h"
#include "AmLcConfig.h"

#include "sip/raw_sender.h"
#include "sip/transport.h"
#include "sip/ip_util.h"

#include <assert.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include "sip/msg_logger.h"
#include "AmSrtpConnection.h"

#define RTCP_PAYLOAD_MIN 72
#define RTCP_PAYLOAD_MAX 76
#define IS_RTCP_PAYLOAD(p) ((p) >= RTCP_PAYLOAD_MIN && (p) <= RTCP_PAYLOAD_MAX)

#define RTCP_PARSE_DEBUG 1

#if RTCP_PARSE_DEBUG==1
#define RTCP_DBG(fmt, args...) DBG(fmt,##args);
#else
    #define RTCP_DBG(fmt, args...) ;
#endif

#define NTP32_TO_USEC_SCALING_FACTOR (1e6/65536.0)

AmRtpPacket::AmRtpPacket()
  : data_offset(0)
{
}

AmRtpPacket::~AmRtpPacket()
{
    //
}

void AmRtpPacket::setAddr(struct sockaddr_storage* a)
{
  memcpy(&saddr,a,sizeof(sockaddr_storage));
}

void AmRtpPacket::getAddr(struct sockaddr_storage* a)
{
  memcpy(a,&saddr,sizeof(sockaddr_storage));
}

void AmRtpPacket::setLocalAddr(struct sockaddr_storage* a)
{
  memcpy(&laddr,a,sizeof(sockaddr_storage));
}

void AmRtpPacket::getLocalAddr(struct sockaddr_storage* a)
{
  memcpy(&laddr,a,sizeof(sockaddr_storage));
}

bool AmRtpPacket::isRtcp()
{
    rtp_hdr_t* hdr = (rtp_hdr_t*)buffer;
    return IS_RTCP_PAYLOAD(hdr->pt);
}

int AmRtpPacket::rtp_parse(AmObject *caller)
{
    assert(buffer);
    assert(b_size);

    rtp_hdr_t* hdr = (rtp_hdr_t*)buffer;
    // ZRTP "Hello" packet has version == 0
    if ((hdr->version != RTP_VERSION) && (hdr->version != 0)) {
        DBG("[%p] received RTP packet with unsupported version (%i).",
            caller,hdr->version);
        return RTP_PACKET_PARSE_ERROR;
    }

    data_offset = sizeof(rtp_hdr_t) + (hdr->cc*4);

    if(hdr->x != 0) {
        if (b_size >= data_offset + 4) {
            data_offset +=
            ntohs(((rtp_xhdr_t*) (buffer + data_offset))->len)*4;
        }
    }

    payload = hdr->pt;

    if(IS_RTCP_PAYLOAD(payload)) {
        return RTP_PACKET_PARSE_RTCP;
    }

    marker = hdr->m;
    sequence = ntohs(hdr->seq);
    timestamp = ntohl(hdr->ts);
    ssrc = ntohl(hdr->ssrc);
    version = hdr->version;

    if (data_offset > b_size) {
        ERROR("[%p] bad rtp packet (hdr-size=%u;pkt-size=%u) !",
              caller,data_offset,b_size);
        return RTP_PACKET_PARSE_ERROR;
    }

    d_size = b_size - data_offset;

    if(hdr->p) {
        if (buffer[b_size-1]>=d_size) {
            ERROR("[%p] bad rtp packet (invalid padding size) !",caller);
            return RTP_PACKET_PARSE_ERROR;
        }
        d_size -= buffer[b_size-1];
    }

    return RTP_PACKET_PARSE_OK;
}

int AmRtpPacket::rtcp_parse_update_stats(RtcpBidirectionalStat &stats)
{
    unsigned char *r, *end, *chunk_end, *p;
    size_t chunk_size;
    int idx;

    assert(buffer);
    assert(b_size);

    r = buffer;
    end = r + b_size;

    //RTCP_DBG("got RTCP with size: %u",b_size);

    idx = 0;
    do {
        chunk_size = end-r;
        if(chunk_size < sizeof(RtcpCommonHeader)) {
            RTCP_DBG("received RTCP packet part %d is too short: %lu (expected %lu)",
                idx,chunk_size,sizeof(RtcpCommonHeader));
            return RTP_PACKET_PARSE_ERROR;
        }

        RtcpCommonHeader &h = *(RtcpCommonHeader *)r;

        if(h.version != RTP_VERSION) {
            //RTCP_DBG("received RTCP packet with wrong version %u",h.version);
            return RTP_PACKET_PARSE_ERROR;
        }

        if(h.p != 0) {
            RTCP_DBG("received RTCP packet with non-zero padding bit");
            return RTP_PACKET_PARSE_ERROR;
        }

        chunk_end = r + sizeof(uint32_t)*(ntohs(h.length) + 1);

        if(chunk_end > end) {
            RTCP_DBG("RTCP%d: too small buffer for provided chunk length value: %d. "
                "expected at least %lu but tail is %lu",
                idx,ntohs(h.length),chunk_end-r,chunk_size);
            return RTP_PACKET_PARSE_ERROR;
        }

        RTCP_DBG("RTCP chunk %d > version: %u, pt: %u, p: %u, count: %u, length: %u(%lu), ssrc: 0x%x",
            idx,
            h.version,
            h.pt,
            h.p,
            h.count,
            ntohs(h.length),chunk_end-r,
            ntohl(h.ssrc));

        switch(h.pt) {
        case RtcpCommonHeader::RTCP_SR:

            RTCP_DBG("RTCP: parse Sender Report");
            if(chunk_size < (sizeof(RtcpCommonHeader)
                             + sizeof(RtcpSenderReportHeader)
                             + h.count*sizeof(RtcpReceiverReportHeader)))
            {
                RTCP_DBG("RTCP: chunk is too small (%lu) to be a valid SenderReport",
                    chunk_size);
                return RTP_PACKET_PARSE_ERROR;
            }

            p = r + sizeof(RtcpCommonHeader);
            process_sender_report(*(RtcpSenderReportHeader*)p,stats);

            if(h.count) {
                p += sizeof(RtcpSenderReportHeader);
                parse_receiver_reports(p,chunk_end-p,stats);
            } else {
                RTCP_DBG("SR with empty RR");
            }

            break;

        case RtcpCommonHeader::RTCP_RR:

            RTCP_DBG("RTCP: parse Receiver Report");
            p = r + sizeof(RtcpCommonHeader);
            if(chunk_size < (sizeof(RtcpCommonHeader)
                             + h.count*sizeof(RtcpReceiverReportHeader)))
            {
                RTCP_DBG("RTCP: chunk is too small (%lu) to be a valid ReceiverReport. RC = %u",
                    chunk_size,h.count);
                return RTP_PACKET_PARSE_ERROR;
            }

            if(h.count)
                parse_receiver_reports(p,chunk_end-p,stats);
            else
                RTCP_DBG("got empty RR");

            break;

        case RtcpCommonHeader::RTCP_SDES:

            RTCP_DBG("RTCP: parse Source Description");
            p = r + sizeof(RtcpCommonHeader);

            if(parse_sdes(p,chunk_end,h.ssrc,stats)) {
                DBG("RTCP: failed to parse SDES packet");
                return RTP_PACKET_PARSE_ERROR;
            }

            break;

        default:
            DBG("RTCP: skip parsing unsupported payload type: %d",h.pt);
        } //switch(h.pt)

        r = chunk_end;
        idx++;

    } while(r < end);

    if (r != end) {
        RTCP_DBG("wrong format of the RTCP compound packet");
    }

    return RTP_PACKET_PARSE_OK;
}


int AmRtpPacket::parse_receiver_reports(unsigned char *chunk,size_t chunk_size, RtcpBidirectionalStat &stats)
{
    unsigned char *end = chunk+chunk_size;
    do {
        process_receiver_report(*(RtcpReceiverReportHeader *)chunk,stats);
        chunk+=sizeof(RtcpReceiverReportHeader);
    } while(chunk < end);
    if(chunk != end) {
        DBG("received reports possibly contain garbage");
    }
    return 0;
}

int AmRtpPacket::parse_sdes(unsigned char *chunk,unsigned char *chunk_end, uint32_t ssrc, RtcpBidirectionalStat &)
{
    u_int8 sdes_type;
    u_int8 sdes_len;

    bool prev_item_is_null = false;

    while (chunk < chunk_end) {
        sdes_type = *chunk++;

        if(chunk==chunk_end)
            break;

        if(sdes_type == RtcpSourceDescriptionHeader::RTCP_SDES_NULL) {
            prev_item_is_null = true;
            continue;
        } else {
            if(prev_item_is_null) {
                prev_item_is_null = false;

                if(chunk + sizeof(uint32_t) > chunk_end)
                    break;

                ssrc = *(uint32_t *)chunk;
                chunk+=sizeof(uint32_t);

                continue;
            }
        }

        sdes_len = *chunk++;

        if (chunk + sdes_len > chunk_end)
            break;

        DBG("RTCP: SDES item %d with value '%.*s' for SSRC 0x%x",
            sdes_type, sdes_len, chunk, ntohl(ssrc));

        chunk += sdes_len;
    }

    return 0;
}

int AmRtpPacket::process_sender_report(RtcpSenderReportHeader &sr, RtcpBidirectionalStat &stats)
{
    stats.lock();

    stats.rtcp_sr_recv++;

    DBG("RTCP SR ntp_sec: %u, ntp_frac: %u, rtp_ts: %u, sender_pcount: %u, sender_bcount: %u",
        ntohl(sr.ntp_sec),
        ntohl(sr.ntp_frac),
        ntohl(sr.rtp_ts),
        ntohl(sr.sender_pcount),
        ntohl(sr.sender_bcount)
    );

    stats.sr_lsr = ( (ntohl(sr.ntp_sec) << 16) |
                     (ntohl(sr.ntp_frac) >> 16) );

    stats.sr_recv_time = recv_time;

    stats.unlock();

    return 0;
}

int AmRtpPacket::process_receiver_report(RtcpReceiverReportHeader &rr, RtcpBidirectionalStat &stats)
{
    stats.lock();

    stats.rtcp_rr_recv++;

    DBG("RTCP RR ssrc: 0x%x, last_seq: %u, lsr: %u,dlsr: %u, jitter: %u, fract_lost: %u, total_lost_0: %u, total_lost_1: %u, total_lost_2: %u",
        ntohl(rr.ssrc),
        ntohl(rr.last_seq),
        ntohl(rr.lsr),
        ntohl(rr.dlsr),
        ntohl(rr.jitter),
        rr.fract_lost,
        rr.total_lost_0,
        rr.total_lost_1,
        rr.total_lost_2
    );

    if(rr.dlsr) {
        //https://tools.ietf.org/search/rfc3550#section-4
        //https://tools.ietf.org/search/rfc3550#section-6.4.1

        int64_t rtt = ((recv_time.tv_sec + NTP_TIME_OFFSET) & 0xffff)*1e6 + recv_time.tv_usec;
        rtt -= ntohl(rr.dlsr)*NTP32_TO_USEC_SCALING_FACTOR;
        rtt -= ntohl(rr.lsr)*NTP32_TO_USEC_SCALING_FACTOR;

        if(rtt > 0) {
            stats.rtt.update(rtt);
        }
    }

    stats.tx.loss = (rr.total_lost_2 << 16) | (rr.total_lost_1 << 8) | rr.total_lost_0;
    DBG("stats.tx.loss: %u",stats.tx.loss);

    if(rr.jitter) {
        stats.rtcp_remote_jitter.update(ntohl(rr.jitter));
    }

    stats.unlock();

    return 0;
}

unsigned char *AmRtpPacket::getData()
{
    return buffer+data_offset;
}

unsigned char *AmRtpPacket::getBuffer()
{
    return buffer;
}

int AmRtpPacket::compile(unsigned char* data_buf, unsigned int size)
{
    assert(data_buf);
    assert(size);

    d_size = size;
    b_size = d_size + sizeof(rtp_hdr_t);
    assert(b_size <= 4096);
    rtp_hdr_t* hdr = (rtp_hdr_t*)buffer;

    if(b_size>sizeof(buffer)) {
        ERROR("builtin buffer size (%d) exceeded: %d",
              (int)sizeof(buffer), b_size);
        return -1;
    }

    memset(hdr,0,sizeof(rtp_hdr_t));
    hdr->version = RTP_VERSION;
    hdr->m = marker;
    hdr->pt = payload;

    hdr->seq = htons(sequence);
    hdr->ts = htonl(timestamp);
    hdr->ssrc = htonl(ssrc);

    data_offset = sizeof(rtp_hdr_t);
    memcpy(&buffer[data_offset],data_buf,d_size);

    return 0;
}

int AmRtpPacket::compile_raw(unsigned char* data_buf, unsigned int size)
{
    if ((!size) || (!data_buf))
        return -1;

    if(size>sizeof(buffer)){
        ERROR("builtin buffer size (%d) exceeded: %d",
              (int)sizeof(buffer), size);
        return -1;
    }

    memcpy(&buffer[0], data_buf, size);
    b_size = d_size = size;
    data_offset = 0;

    return size;
}

void AmRtpPacket::setBuffer(unsigned char* buf, unsigned int b)
{
    memcpy(buffer, buf, b);
    b_size = b;
}

void AmRtpPacket::setBufferSize(unsigned int b)
{
    b_size = b;
}

void AmRtpPacket::logReceived(msg_logger *logger, struct sockaddr_storage *laddr)
{
    static const cstring empty;
    logger->log((const char *)buffer, b_size, &saddr, laddr, empty);
}

void AmRtpPacket::logSent(msg_logger *logger, struct sockaddr_storage *laddr)
{
    static const cstring empty;
    logger->log((const char *)buffer, b_size, laddr, &saddr, empty);
}

void AmRtpPacket::mirrorReceived(msg_sensor *sensor, struct sockaddr_storage *laddr){
    sensor->feed((const char *)buffer, b_size, &saddr, laddr, msg_sensor::PTYPE_RTP);
}

void AmRtpPacket::mirrorSent(msg_sensor *sensor, struct sockaddr_storage *laddr){
    sensor->feed((const char *)buffer, b_size, laddr, &saddr, msg_sensor::PTYPE_RTP);
}


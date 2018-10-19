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

#define RTCP_PAYLOAD_MIN 72
#define RTCP_PAYLOAD_MAX 76
#define IS_RTCP_PAYLOAD(p) ((p) >= RTCP_PAYLOAD_MIN && (p) <= RTCP_PAYLOAD_MAX)

#define RTCP_PARSE_DEBUG 1

#if RTCP_PARSE_DEBUG==1
#define RTCP_DBG(fmt, args...) DBG(fmt,##args);
#else
    #define RTCP_DBG(fmt, args...) ;
#endif

AmRtpPacket::AmRtpPacket()
  : data_offset(0),
    relayed(false)
{
    // buffer will be overwritten by received packet
    // of hdr+data - does not need to be set to 0s
    //    memset(buffer,0,4096);

    recv_iov[0].iov_base = buffer;
    recv_iov[0].iov_len  = RTP_PACKET_BUF_SIZE;

    memset(&recv_msg,0,sizeof(recv_msg));

    recv_msg.msg_name       = &addr;
    recv_msg.msg_namelen    = sizeof(struct sockaddr_storage);

    recv_msg.msg_iov        = recv_iov;
    recv_msg.msg_iovlen     = 1;

    recv_msg.msg_control    = recv_ctl_buf;
    recv_msg.msg_controllen = RTP_PACKET_TIMESTAMP_DATASIZE;
}

AmRtpPacket::~AmRtpPacket()
{
    //
}

void AmRtpPacket::setAddr(struct sockaddr_storage* a)
{
  memcpy(&addr,a,sizeof(sockaddr_storage));
}

void AmRtpPacket::getAddr(struct sockaddr_storage* a)
{
  memcpy(a,&addr,sizeof(sockaddr_storage));
}

int AmRtpPacket::rtp_parse(AmObject *caller)
{
    assert(buffer);
    assert(b_size);

    rtp_hdr_t* hdr = (rtp_hdr_t*)buffer;
    // ZRTP "Hello" packet has version == 0
    if ((hdr->version != RTP_VERSION) && (hdr->version != 0)) {
        DBG("[%p] received RTP packet with unsupported version (%i).\n",
            caller,hdr->version);
        return RTP_PACKET_PARSE_ERROR;
    }

    data_offset = sizeof(rtp_hdr_t) + (hdr->cc*4);

    if(hdr->x != 0) {
        //#ifndef WITH_ZRTP
        //if (AmConfig::IgnoreRTPXHdrs) {
        //  skip the extension header
        //#endif
        if (b_size >= data_offset + 4) {
            data_offset +=
            ntohs(((rtp_xhdr_t*) (buffer + data_offset))->len)*4;
        }
        // #ifndef WITH_ZRTP
        //   } else {
        //     DBG("RTP extension headers not supported.\n");
        //     return -1;
        //   }
        // #endif
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
        ERROR("[%p] bad rtp packet (hdr-size=%u;pkt-size=%u) !\n",
              caller,data_offset,b_size);
        return RTP_PACKET_PARSE_ERROR;
    }
    d_size = b_size - data_offset;

    if(hdr->p) {
        if (buffer[b_size-1]>=d_size) {
            ERROR("[%p] bad rtp packet (invalid padding size) !\n",caller);
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

    RTCP_DBG("got RTCP with size: %u",b_size);

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
            RTCP_DBG("received RTCP packet with wrong version %u",h.version);
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

    uint32_t ssrc = ntohl(rr.ssrc);
    DBG("RTCP RR ssrc: 0x%x, last_seq: %u, lsr: %u,dlsr: %u, jitter: %u, fract_lost: %u, total_lost_0: %u, total_lost_1: %u, total_lost_2: %u",
        ssrc,
        ntohl(rr.last_seq),
        ntohl(rr.lsr),
        ntohl(rr.dlsr),
        ntohl(rr.jitter),
        rr.fract_lost,
        rr.total_lost_0,
        rr.total_lost_1,
        rr.total_lost_2
    );

    stats.unlock();

    return 0;
}

unsigned char *AmRtpPacket::getData()
{
    return &buffer[data_offset];
}

unsigned char *AmRtpPacket::getBuffer()
{
    return &buffer[0];
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
        ERROR("builtin buffer size (%d) exceeded: %d\n",
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
        ERROR("builtin buffer size (%d) exceeded: %d\n",
              (int)sizeof(buffer), size);
        return -1;
    }

    memcpy(&buffer[0], data_buf, size);
    b_size = size;

    return size;
}

int AmRtpPacket::sendto(int sd)
{
    int err = ::sendto(sd,buffer,b_size,0,
                       (const struct sockaddr *)&addr,
                       SA_len(&addr));

    if(err == -1){
        ERROR("while sending RTP packet with sendto(%d,%p,%d,0,%p,%ld): %s\n",
              sd,buffer,b_size,&addr,SA_len(&addr),
              strerror(errno));
        log_stacktrace(L_DBG);
        return -1;
    }

    return 0;
}

int AmRtpPacket::sendmsg(int sd, unsigned int sys_if_idx)
{
  struct msghdr hdr;
  struct cmsghdr* cmsg;
    
  union {
    char cmsg4_buf[CMSG_SPACE(sizeof(struct in_pktinfo))];
    char cmsg6_buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
  } cmsg_buf;

  struct iovec msg_iov[1];
  msg_iov[0].iov_base = (void*)buffer;
  msg_iov[0].iov_len  = b_size;

  bzero(&hdr,sizeof(hdr));
  hdr.msg_name = (void*)&addr;
  hdr.msg_namelen = SA_len(&addr);
  hdr.msg_iov = msg_iov;
  hdr.msg_iovlen = 1;

  bzero(&cmsg_buf,sizeof(cmsg_buf));
  hdr.msg_control = &cmsg_buf;
  hdr.msg_controllen = sizeof(cmsg_buf);

  cmsg = CMSG_FIRSTHDR(&hdr);
  if(addr.ss_family == AF_INET) {
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

    struct in_pktinfo* pktinfo = (struct in_pktinfo*) CMSG_DATA(cmsg);
    pktinfo->ipi_ifindex = sys_if_idx;
  }
  else if(addr.ss_family == AF_INET6) {
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    
    struct in6_pktinfo* pktinfo = (struct in6_pktinfo*) CMSG_DATA(cmsg);
    pktinfo->ipi6_ifindex = sys_if_idx;
  }

  hdr.msg_controllen = cmsg->cmsg_len;
  
  // bytes_sent = ;
  if(::sendmsg(sd, &hdr, 0) < 0) {
      ERROR("sendto: %s\n",strerror(errno));
      return -1;
  }

  return 0;
}

/*int AmRtpPacket::send(int sd, unsigned int sys_if_idx,
			  sockaddr_storage* l_saddr)*/
int AmRtpPacket::send(int sd, const MEDIA_info &iface,
			  sockaddr_storage* l_saddr)

{
  unsigned int sys_if_idx = iface.net_if_idx;

  if(sys_if_idx && iface.sig_sock_opts&trsp_socket::use_raw_sockets) {
    return raw_sender::send((char*)buffer,b_size,sys_if_idx,l_saddr,&addr,iface.tos_byte);
  }

  if(sys_if_idx && AmConfig.force_outbound_if) {
    return sendmsg(sd,sys_if_idx);
  }
  
  return sendto(sd);
}

int AmRtpPacket::recv(int sd)
{
    relayed = false;

    /*
    socklen_t recv_addr_len = sizeof(struct sockaddr_storage);
    int ret = recvfrom(sd,buffer,sizeof(buffer),0,
                       (struct sockaddr*)&addr, &recv_addr_len);
    */

    cmsghdr *cmsgptr;
    int ret = recvmsg(sd,&recv_msg,0);

    for (cmsgptr = CMSG_FIRSTHDR(&recv_msg);
        cmsgptr != NULL;
        cmsgptr = CMSG_NXTHDR(&recv_msg, cmsgptr))
    {
        if(cmsgptr->cmsg_level == SOL_SOCKET &&
           cmsgptr->cmsg_type == SO_TIMESTAMP)
        {
            memcpy(&recv_time, CMSG_DATA(cmsgptr), sizeof(struct timeval));
        }
    }

    if(ret > 0) {
        if(ret > 4096)
            return -1;
        b_size = ret;
    }

    return ret;
}

void AmRtpPacket::logReceived(msg_logger *logger, struct sockaddr_storage *laddr)
{
    static const cstring empty;
    logger->log((const char *)buffer, b_size, &addr, laddr, empty);
}

void AmRtpPacket::logSent(msg_logger *logger, struct sockaddr_storage *laddr)
{
    static const cstring empty;
    logger->log((const char *)buffer, b_size, laddr, &addr, empty);
}

void AmRtpPacket::mirrorReceived(msg_sensor *sensor, struct sockaddr_storage *laddr){
    sensor->feed((const char *)buffer, b_size, &addr, laddr, msg_sensor::PTYPE_RTP);
}

void AmRtpPacket::mirrorSent(msg_sensor *sensor, struct sockaddr_storage *laddr){
    sensor->feed((const char *)buffer, b_size, laddr, &addr, msg_sensor::PTYPE_RTP);
}


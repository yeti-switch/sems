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
/** @file AmRtpPacket.h */
#ifndef _AmRtpPacket_h_
#define _AmRtpPacket_h_

#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "AmLcConfig.h"
#include "sip/msg_sensor.h"
#include "rtcp/RtcpStat.h"
#include "rtcp/RtcpPacket.h"

class AmRtpPacketTracer;
class AmSrtpConnection;
class msg_logger;

#define RTP_PACKET_PARSE_ERROR -1
#define RTP_PACKET_PARSE_OK 0
#define RTP_PACKET_PARSE_RTCP 1

#define RTP_PACKET_BUF_SIZE 4096
#define RTP_PACKET_TIMESTAMP_DATASIZE (CMSG_SPACE(sizeof(struct timeval)))

//seconds between 1900-01-01 and 1970-01-01
//(70*365 + 17)*86400
#define NTP_TIME_OFFSET 2208988800ULL

/** \brief RTP packet implementation */
class AmRtpPacket
{
    unsigned char  buffer[RTP_PACKET_BUF_SIZE];
    unsigned int   b_size;

    unsigned int   data_offset;
    unsigned int   d_size;

  public:
    unsigned char  payload;
    bool           marker;
    unsigned short sequence;
    unsigned int   timestamp;
    unsigned int   ssrc;
    unsigned char  version;
    bool           relayed;

    struct sockaddr_storage saddr;
    struct sockaddr_storage laddr;
    struct timeval recv_time;

    AmRtpPacket();
    ~AmRtpPacket();

    void setAddr(struct sockaddr_storage* a);
    void getAddr(struct sockaddr_storage* a);
    void setLocalAddr(struct sockaddr_storage* a);
    void getLocalAddr(struct sockaddr_storage* a);

    // returns -1 if error, else 0
    int compile(unsigned char* data_buf, unsigned int size);
    // returns -1 if error, else size
    int compile_raw(unsigned char* data_buf, unsigned int size);
    int compile_raw(const std::vector<iovec> &iovecs);

    int rtp_parse(AmObject *caller = NULL);
    bool isRtcp();

    int rtcp_parse_update_stats(RtcpBidirectionalStat &stats);
    int parse_receiver_reports(unsigned char *chunk,size_t chunk_size, RtcpBidirectionalStat &stats);
    int parse_sdes(unsigned char *chunk,unsigned char *chunk_end, uint32_t ssrc, RtcpBidirectionalStat &stats);

    int process_sender_report(RtcpSenderReportHeader &sr, RtcpBidirectionalStat &stats);
    int process_receiver_report(RtcpReceiverReportHeader &rr, RtcpBidirectionalStat &stats);

    /*void update_receiver_stats(RtcpBidirectionalStat &stats);
    void update_sender_stats(RtcpBidirectionalStat &stats);*/

    unsigned int   getDataSize() const { return d_size; }
    unsigned char* getData();

    unsigned int   getBufferSize() const { return b_size; }
    unsigned char* getBuffer();
    void logReceived(msg_logger *logger, struct sockaddr_storage *laddr);
    void logSent(msg_logger *logger, struct sockaddr_storage *laddr);

    void mirrorReceived(msg_sensor *sensor, struct sockaddr_storage *laddr);
    void mirrorSent(msg_sensor *sensor, struct sockaddr_storage *laddr);
    void setBuffer(unsigned char* buf, unsigned int b);
    void setBufferSize(unsigned int b);
};

#endif



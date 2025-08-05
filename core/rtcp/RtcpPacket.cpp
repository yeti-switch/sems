#include "RtcpPacket.h"

#include <string.h>

#define RTCP_ALIGN_BYTES 4
#define TO_RTCP_LENGTH(expr) htons(((expr) >> 2) - 1)

void RtcpReportsPreparedData::init(unsigned int l_ssrc, const string& cname)
{
    bzero(this,sizeof(RtcpReportsPreparedData));

    RtcpSdesData &sdes =  rr_empty.sdes;
    RtcpCommonHeader &rrh = rr_empty.rr.header;

    //init SDES CNAME item
    sdes.item.type = RtcpSourceDescriptionHeader::RTCP_SDES_CNAME;
    if (!cname.empty() && cname.size() <= INET6_ADDRSTRLEN) {
        sdes.item.len = cname.size();
        memcpy(sdes.data, cname.data(), cname.size());
    } else {
        sdes.item.len = 0;
    }

    sdes.packet_length =
        sizeof(sdes.header) +
        sizeof(sdes.item) +
        sdes.item.len;

    //add SDES END item
    sdes.packet_length += 1;

    //add padding to 32bit border
    sdes.packet_length = (sdes.packet_length + RTCP_ALIGN_BYTES - 1) / RTCP_ALIGN_BYTES * RTCP_ALIGN_BYTES;

    { //init empty RR header
        RtcpCommonHeader &h = rrh;
        h.version = 2;
        h.p = 0;
        h.pt = RtcpCommonHeader::RTCP_RR;
        h.count = 0;
        h.length = TO_RTCP_LENGTH(sizeof(rr_empty.rr));
        h.ssrc = htonl(l_ssrc);
    }

    //update empty RR packet_length
    rr_empty.packet_length = sizeof(rr_empty.rr) + sdes.packet_length;

    { //init RR SDES chunk header
        RtcpCommonHeader &h = sdes.header;

        memcpy(&h, &rrh, sizeof(rrh));

        h.pt = RtcpCommonHeader::RTCP_SDES;
        h.count = 1;
        h.length = TO_RTCP_LENGTH(sdes.packet_length);
    }

    { //init RR
        RtcpCommonHeader &h = rr.rr.header;

        memcpy(&h, &rrh, sizeof(rrh));

        h.count = 1;
        h.length = TO_RTCP_LENGTH(sizeof(rr.rr));

        memcpy(&rr.sdes, &sdes, sizeof(sdes));

        rr.packet_length = sizeof(rr.rr) + sdes.packet_length;
    }

    { //init empty SR
        RtcpCommonHeader &h = sr_empty.sr.header;

        memcpy(&h, &rrh, sizeof(rrh));

        h.pt = RtcpCommonHeader::RTCP_SR;
        h.length = TO_RTCP_LENGTH(sizeof(sr_empty.sr));

        memcpy(&sr_empty.sdes, &sdes, sizeof(sdes));

        sr_empty.packet_length = sizeof(sr_empty.sr) + sdes.packet_length;
    }

    { //init SR
        RtcpCommonHeader &h = sr.sr.header;

        memcpy(&h, &rrh, sizeof(rrh));

        h.pt = RtcpCommonHeader::RTCP_SR;
        h.count = 1;
        h.length = TO_RTCP_LENGTH(sizeof(sr.sr));

        memcpy(&sr.sdes, &sdes, sizeof(sdes));

        sr.packet_length = sizeof(sr.sr) + sdes.packet_length;
    }
}

void RtcpReportsPreparedData::update(unsigned int r_ssrc)
{
    rr.rr.receiver.ssrc = htonl(r_ssrc);
    sr.sr.receiver.ssrc = rr.rr.receiver.ssrc;
}

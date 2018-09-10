#include "RtcpPacket.h"

#include <string.h>

void RtcpReportsPreparedData::init(unsigned int l_ssrc)
{
    bzero(this,sizeof(RtcpReportsPreparedData));

    RtcpSdesData &sdes =  rr_empty.sdes;
    RtcpCommonHeader &rrh = rr_empty.rr.header;

    { //init empty RR header
        RtcpCommonHeader &h = rrh;
        h.version = 2;
        h.p = 0;
        h.pt = RtcpCommonHeader::RTCP_RR;
        h.count = 0;
        h.length = htons((sizeof(rr_empty.rr) >> 2) - 1);
        h.ssrc = htonl(l_ssrc);
    }

    { //init empty RR SDES chunk
        RtcpCommonHeader &h = sdes.header;

        memcpy(&h, &rrh, sizeof(rrh));

        h.pt = RtcpCommonHeader::RTCP_SDES;
        h.count = 1;
        h.length = htons((sizeof(rr_empty.sdes) >> 2) - 1);

        sdes.item.type = RtcpSourceDescriptionHeader::RTCP_SDES_CNAME;
        sdes.item.len = 0;
    }

    { //init RR
        RtcpCommonHeader &h = rr.rr.header;

        memcpy(&h, &rrh, sizeof(rrh));

        h.count = 1;
        h.length = htons((sizeof(rr.rr) >> 2) - 1);

        memcpy(&rr.sdes, &sdes, sizeof(sdes));
    }

    { //init empty SR
        RtcpCommonHeader &h = sr_empty.sr.header;

        memcpy(&h, &rrh, sizeof(rrh));

        h.pt = RtcpCommonHeader::RTCP_SR;
        h.length = htons((sizeof(sr_empty.sr) >> 2) - 1);

        memcpy(&sr_empty.sdes, &sdes, sizeof(sdes));
    }

    { //init SR
        RtcpCommonHeader &h = sr.sr.header;

        memcpy(&h, &rrh, sizeof(rrh));

        h.pt = RtcpCommonHeader::RTCP_SR;
        h.count = 1;
        h.length = htons((sizeof(sr.sr) >> 2) - 1);

        memcpy(&sr.sdes, &sdes, sizeof(sdes));
    }
}

void RtcpReportsPreparedData::update(unsigned int r_ssrc)
{
    rr.rr.receiver.ssrc = htonl(r_ssrc);
    sr.sr.receiver.ssrc = rr.rr.receiver.ssrc;
}

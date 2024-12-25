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

#include "AmRtpStream.h"
#include "media/AmSrtpConnection.h"
#include "AmRtpPacket.h"
#include "AmLcConfig.h"
#include "AmPlugIn.h"
#include "AmAudio.h"
#include "AmUtils.h"
#include "AmSession.h"
#include "AmDtmfDetector.h"
#include "rtp/telephone_event.h"
#include "amci/codecs.h"

#include "sip/resolver.h"
#include "sip/ip_util.h"
#include "sip/transport.h"
#include "sip/msg_logger.h"

#include "bitops.h"
#include "log.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "rtp/rtp.h"

#include <set>
using std::set;
#include <algorithm>
#include <sstream>

#define ts_unsigned_diff(a,b) ((a)>=(b) ? (a)-(b) : (b)-(a))

//max_frame_size * 20
#define RTP_TIMESTAMP_ALINGING_MAX_TS_DIFF (200*20)

#define RTCP_REPORT_SEND_INTERVAL_SECONDS 3
#define ICE_PWD_SIZE    22
#define ICE_UFRAG_SIZE  4

#define BIND_ATTEMPTS_COUNT 10

#define MAX_TRANSPORTS_COUNT 8

static inline void add_if_no_exist(std::vector<int> &v,int payload)
{
    if(std::find(v.begin(),v.end(),payload)==v.end())
        v.push_back(payload);
}

void PayloadMask::clear()
{
    memset(bits, 0, sizeof(bits));
}

void PayloadMask::set_all()
{
    memset(bits, 0xFF, sizeof(bits));
}

void PayloadMask::invert()
{
    // assumes that bits[] contains 128 bits
    unsigned long long* ull = (unsigned long long*)bits;
    ull[0] = ~ull[0];
    ull[1] = ~ull[1];
}

PayloadMask::PayloadMask(const PayloadMask &src)
{
    memcpy(bits, src.bits, sizeof(bits));
}

void PayloadRelayMap::clear()
{
    memset(map, 0, sizeof(map));
}

PayloadRelayMap::PayloadRelayMap(const PayloadRelayMap &src)
{
    memcpy(map, src.map, sizeof(map));
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                   constructor, destructor

AmRtpStream::AmRtpStream(AmSession* _s, int _if)
    : tx_user_ts(0),
    last_send_rtcp_report_ts(0),
    dropped_packets_count(0),
    incoming_bytes(0),
    outgoing_bytes(0), // do not return any data unless something really received
    rtp_parse_errors(0),
    out_of_buffer_errors(0),
    srtp_unprotect_errors(0),
    last_not_supported_rx_payload(-1),
    last_not_supported_tx_payload(-1),
    wrong_payload_errors(0),
    dead_rtp_time(AmConfig.dead_rtp_time),
    relay_ts_shift(0),
    sdp_media_index(-1),
    last_recv_payload(-1),
    last_recv_relayed(false),
    last_recv_ts(0),
    l_if(_if),
    r_ssrc_i(false),
    transport(TP_RTPAVP),
    is_ice_stream(false),
    ice_controlled(false),
    cur_rtp_trans(0),
    cur_rtcp_trans(0),
    cur_udptl_trans(0),
    monitor_rtp_timeout(true),
    mute(false),
    sending(true),
    receiving(true),
    relay_enabled(false),
    relay_raw(false),
    relay_stream(NULL),
    relay_transparent_seqno(false),
    relay_transparent_ssrc(false),
    relay_filter_dtmf(false),
    force_relay_dtmf(true),
    relay_timestamp_aligning(false),
    symmetric_rtp_endless(false),
    symmetric_rtp_enable(false),
    symmetric_candidate_enable(true),
    rtp_endpoint_learned_notified(false),
    rtp_ping(false),
    force_buffering(false),
    session(_s),
    offer_answer_used(true),
    active(false),
    multiplexing(false),
    reuse_media_trans(true),
    force_receive_dtmf(false)
{
    DBG("AmRtpStream[%p](%p)",this,session);

    l_ssrc = get_random();
    sequence = get_random();
    ((uint32_t*)&ice_tiebreaker)[0] = get_random();
    ((uint32_t*)&ice_tiebreaker)[1] = get_random();
    clearRTPTimeout();

    // by default the system codecs
    payload_provider = AmPlugIn::instance();
#ifdef WITH_ZRTP
    zrtp_context.addSubscriber(this);
#endif/*WITH_ZRTP*/

    bzero(local_telephone_event_payloads, sizeof(local_telephone_event_payloads));

    if(_s) {
        setMultiplexing(_s->isRtcpMultiplexing());
    }
}

AmRtpStream::~AmRtpStream()
{
    DBG("~AmRtpStream[%p]() session = %p",this,session);
    if(session) session->onRTPStreamDestroy(this);
    for(int i = 0; i < MAX_TRANSPORT_TYPE; i++)
        ice_context[i].reset(nullptr);
    iterateTransports([](auto tr) { delete tr; });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                   initialisation functions

int AmRtpStream::getRPort(int type)
{
    if(type == RTCP_TRANSPORT && cur_rtcp_trans) return cur_rtcp_trans->getRPort(true);
    else if(type == RTP_TRANSPORT && cur_rtp_trans) return cur_rtp_trans->getRPort(false);
    else if(type == FAX_TRANSPORT && cur_udptl_trans) return cur_udptl_trans->getRPort(false);
    return 0;
}

string AmRtpStream::getRHost(int type)
{
    if(type == RTCP_TRANSPORT && cur_rtcp_trans) return cur_rtcp_trans->getRHost(true);
    else if(type == RTP_TRANSPORT && cur_rtp_trans) return cur_rtp_trans->getRHost(false);
    else if(type == FAX_TRANSPORT && cur_udptl_trans) return cur_udptl_trans->getRHost(false);
    return "";
}

inline string addr_t_2_str(int at)
{
    switch(at){
        case AT_V4: return "IPv4";
        case AT_V6: return "IPv6";
        default: return "<unknown address type>";
    }
}

void AmRtpStream::setLocalIP(AddressType addrtype)
{
    if(l_if < 0) {
        if (session) l_if = session->getRtpInterface();
        else {
            CLASS_ERROR("BUG: no session when initializing RTP stream, invalid interface can be used");
            l_if = 0;
        }
    }

    if(addrtype == AT_NONE)
        addrtype = session->getLocalMediaAddressType();

    vector<AmMediaTransport*>* transports;
    if(addrtype == AT_V4) {
        initIP4Transport();
        transports = &ip4_transports;
    } else {
        initIP6Transport();
        transports = &ip6_transports;
    }

    for(auto transport : *transports) {
        if(transport->getTransportType() == RTP_TRANSPORT) {
            CLASS_DBG("set current rtp transport %p", transport);
            cur_rtp_trans = transport;
            continue;
        }

        if(transport->getTransportType() == FAX_TRANSPORT) {
            CLASS_DBG("set current udptl transport %p", transport);
            cur_udptl_trans = transport;
            continue;
        }

        if(transport->getTransportType() == RTCP_TRANSPORT) {
            CLASS_DBG("set current rtcp transport %p", transport);
            cur_rtcp_trans = transport;
            continue;
        }
    }

    if(!cur_rtp_trans) {
        CLASS_ERROR("[%s] AmRtpStream:setLocalIP on the interface(%d): "
            "failed to get transport for the address type %s",
            getSessionLocalTag(),
            l_if, addr_t_2_str(addrtype).c_str());
        string error("failed to get transport for the address type: " );
        error += addr_t_2_str(addrtype);
        throw error;
    }

    if(!cur_rtcp_trans) {
        cur_rtcp_trans = cur_rtp_trans;
    }

    if(!cur_udptl_trans) {
        cur_udptl_trans = cur_rtp_trans;
    }
}

std::string AmRtpStream::getLocalIP()
{
    if(!cur_rtp_trans || !cur_rtcp_trans || !cur_udptl_trans) {
        setLocalIP();
    }

    if(!cur_rtp_trans || !cur_rtcp_trans || !cur_udptl_trans) {
        ERROR("AmRtpStream:getLocalIP. failed to get transport");
        return 0;
    }

    if(transport == TP_UDPTL)
        return cur_udptl_trans->getLocalIP();
    else
        return cur_rtp_trans->getLocalIP();
}

std::string AmRtpStream::getLocalAddress()
{
    if(!cur_rtp_trans || !cur_rtcp_trans || !cur_udptl_trans) {
        setLocalIP();
    }

    if(!cur_rtp_trans || !cur_rtcp_trans || !cur_udptl_trans) {
        ERROR("AmRtpStream:getLocalPort. failed to get transport");
        return "";
    }

    if(transport == TP_UDPTL) {
        string &host = AmConfig
            .media_ifs[l_if]
            .proto_info[cur_udptl_trans->getLocalProtoId()]->getAdvertisedHost();
        if(host.empty())
            return cur_udptl_trans->getLocalIP();
        return host;
    } else {
        string &host = AmConfig
            .media_ifs[l_if]
            .proto_info[cur_rtp_trans->getLocalProtoId()]->getAdvertisedHost();
        if(host.empty())
            return cur_rtp_trans->getLocalIP();
        return host;
    }
    return "";
}

int AmRtpStream::getLocalPort()
{
    if(!cur_rtp_trans || !cur_rtcp_trans || !cur_udptl_trans) {
        setLocalIP();
    }

    if(!cur_rtp_trans || !cur_rtcp_trans || !cur_udptl_trans) {
        ERROR("AmRtpStream:getLocalPort. failed to get transport");
        return 0;
    }

    if(transport == TP_UDPTL)
        return cur_udptl_trans->getLocalPort();
    else
        return cur_rtp_trans->getLocalPort();
}

int AmRtpStream::getLocalRtcpPort()
{
    if(!cur_rtp_trans || !cur_rtcp_trans || !cur_udptl_trans) {
        setLocalIP();
    }

    if(!cur_rtp_trans || !cur_rtcp_trans || !cur_udptl_trans) {
        ERROR("AmRtpStream:getLocalRtcpPort. failed to get transport");
        return 0;
    }

    return cur_rtcp_trans->getLocalPort();
}

void AmRtpStream::calcRtpPorts(AmMediaTransport* tr_rtp, AmMediaTransport* tr_rtcp)
{
    assert(tr_rtp);

    if(tr_rtp->getLocalPort() && tr_rtcp && tr_rtcp->getLocalPort())
        return;

    sockaddr_storage l_rtcp_addr, l_rtp_addr;
    int retry = BIND_ATTEMPTS_COUNT;
    for(;retry; --retry) {

        if (!tr_rtp->getLocalSocket() ||
            (tr_rtcp && !tr_rtcp->getLocalSocket()))
        {
            return;
        }

        if(!AmConfig.getMediaProtoInfo(
            tr_rtp->getLocalIf(),
            tr_rtp->getLocalProtoId()).getNextRtpAddress(l_rtp_addr))
        {
            //no free ports in PortMap. give up
            throw string("no free RTP ports");
        }

        if(tr_rtp != tr_rtcp && tr_rtcp) {
            memcpy(&l_rtcp_addr, &l_rtp_addr, sizeof(sockaddr_storage));
            am_set_port(&l_rtcp_addr,am_get_port(&l_rtp_addr)+1);

            //bind RTCP port
            if(bind(
                tr_rtcp->getLocalSocket(),
                (const struct sockaddr*)&l_rtcp_addr,
                SA_len(&l_rtcp_addr)))
            {
                CLASS_ERROR("failed to bind port %d for RTCP: %s",
                          am_get_port(&l_rtp_addr)+1, strerror(errno));
                goto try_another_port;
            }
        }

        //bind RTP port
        if(bind(
            tr_rtp->getLocalSocket(),
            (const struct sockaddr*)&l_rtp_addr,
            SA_len(&l_rtp_addr)))
        {
            CLASS_ERROR("failed to bind port %hu for RTP: %s",
                        am_get_port(&l_rtp_addr), strerror(errno));
            goto try_another_port;
        }

        // both bind() succeeded!
        // rco: does that make sense after bind() ????
        tr_rtp->setLocalAddr(&l_rtp_addr);
        if(tr_rtp != tr_rtcp && tr_rtcp) {
            tr_rtcp->setLocalAddr(&l_rtcp_addr);
        }
        break;

try_another_port:
        AmConfig.getMediaProtoInfo(
            tr_rtp->getLocalIf(),
            tr_rtp->getLocalProtoId()).freeRtpAddress(l_rtp_addr);

        tr_rtp->getLocalSocket(true);
        if(tr_rtp != tr_rtcp && tr_rtcp) {
            tr_rtcp->getLocalSocket(true);
        }
    }

    if (!retry) {
        ERROR("could not bind RTP/RTCP ports considered free after %d attempts",
              BIND_ATTEMPTS_COUNT);
        throw string("could not find a free RTP port");
    }

}

void AmRtpStream::setRAddr(const string& addr, unsigned short port)
{
    //ignore setting raddr for ice streams
    if(isIceStream()) { return; }

    CLASS_DBG("RTP remote address set to %s:%u", addr.c_str(),port);

    bool find_transport = true;
    sockaddr_storage raddr, laddr;
    am_inet_pton(addr.c_str(), &raddr);
    AmMediaTransport *cur_transport = 0;
    if(transport != TP_UDPTL && cur_rtp_trans)
        cur_transport = cur_rtp_trans;
    else
        cur_transport = cur_udptl_trans;

    if(cur_transport) {
        cur_transport->getLocalAddr(&laddr);
        find_transport = (laddr.ss_family != raddr.ss_family);
    }

    if(!find_transport) {
        cur_transport->setRAddr(addr, port);
        mute = cur_transport->isMute(AmStreamConnection::RAW_CONN);
    }
}

void AmRtpStream::addAdditionTransport()
{
    if(reuse_media_trans) {
        return;
    }

    if(!cur_rtp_trans || !cur_rtcp_trans || !cur_udptl_trans) {
        setLocalIP();
    }

    if(!cur_rtp_trans || !cur_rtcp_trans || !cur_udptl_trans) {
        ERROR("AmRtpStream::addAdditionTransport. failed to get transport");
        return;
    }

    vector<AmMediaTransport*>* transports;
    AddressType type;
    sockaddr_storage sa;
    cur_rtp_trans->getLocalAddr(&sa);
    if(sa.ss_family == AF_INET) {
        transports = &ip4_transports;
        type = AT_V4;
    } else {
        transports = &ip6_transports;
        type = AT_V6;
    }

    int proto_id = AmConfig.media_ifs[l_if].findProto(type,MEDIA_info::RTP);
    if(proto_id < 0) {
        CLASS_DBG("[%s] AmRtpTransport: missed requested %s proto "
            "in the chosen media interface %d",
            getSessionLocalTag(),
            addr_t_2_str(type).data(), l_if);
    } else if((!multiplexing && transports->size() < 3) &&
              (multiplexing && transports->size() < 2)){
        AmMediaTransport  *fax = new AmMediaTransport(this, l_if, proto_id, FAX_TRANSPORT);
        transports->push_back(fax);
        calcRtpPorts(fax, 0);
    }
}

void AmRtpStream::initIP4Transport()
{
    if(!ip4_transports.empty())
        return;

    int proto_id = AmConfig.media_ifs[l_if].findProto(AT_V4,MEDIA_info::RTP);
    if(proto_id < 0) {
        CLASS_ERROR("[%s] AmRtpTransport: missed requested IPv4 proto "
            "in the chosen media interface %d",
            getSessionLocalTag(),
            l_if);
    } else {
        AmMediaTransport *rtp = new AmMediaTransport(this, l_if, proto_id, RTP_TRANSPORT),
                         *rtcp = 0;
        ip4_transports.push_back(rtp);
        if(!multiplexing) {
            rtcp = new AmMediaTransport(this, l_if, proto_id, RTCP_TRANSPORT);
            ip4_transports.push_back(rtcp);
        }
        calcRtpPorts(rtp, rtcp);
    }
}
void AmRtpStream::initIP6Transport()
{
    if(!ip6_transports.empty())
        return;

    int proto_id = AmConfig.media_ifs[l_if].findProto(AT_V6,MEDIA_info::RTP);
    if(proto_id < 0) {
        CLASS_ERROR("[%s] AmRtpTransport: missed requested IPv6 proto "
            "in the chosen media interface %d",
            getSessionLocalTag(),
            l_if);
    } else {
        AmMediaTransport *rtp = new AmMediaTransport(this, l_if, proto_id, RTP_TRANSPORT),
                         *rtcp = 0;
        ip6_transports.push_back(rtp);
        if(!multiplexing) {
            rtcp = new AmMediaTransport(this, l_if, proto_id, RTCP_TRANSPORT);
            ip6_transports.push_back(rtcp);
        }
        calcRtpPorts(rtp, rtcp);
    }
}

void AmRtpStream::setCurrentTransport(AmMediaTransport* transport)
{
    if(!transport) return;
    if(transport->getTransportType() == RTP_TRANSPORT) {
        cur_rtp_trans = transport;
        if(!cur_rtcp_trans && multiplexing) {
            cur_rtcp_trans = transport;
        }
    } else if(transport->getTransportType() == RTCP_TRANSPORT) {
        cur_rtcp_trans = transport;
    }
}

void AmRtpStream::onSrtpKeysAvailable(int transport_type, uint16_t srtp_profile, const string& local_key, const string& remote_key)
{
    CLASS_DBG("onSrtpKeysAvailable() stream:%p, transport:%d", to_void(this), transport_type);
    iterateTransports([&](auto tr){
        if(transport_type != tr->getTransportType() || !tr->isSrtpEnable())
            return;

        CLASS_DBG("onSrtpKeysAvailable() stream:%p, state:%s, type:%s", to_void(this), tr->state2str(), tr->type2str());
        tr->getConnFactory()->store_srtp_cred(srtp_profile, local_key, remote_key);
        tr->onSrtpKeysAvailable();
    });
}

void AmRtpStream::iterateTransports(std::function<void(AmMediaTransport* transport)> iterator)
{
    for(auto tr : ip4_transports) iterator(tr);
    for(auto tr : ip6_transports) iterator(tr);
}

void AmRtpStream::initIce()
{
    if(!ice_context[RTP_TRANSPORT])
            ice_context[RTP_TRANSPORT].reset(new IceContext(this, RTP_TRANSPORT));
    if(!ice_context[RTCP_TRANSPORT] && !multiplexing)
            ice_context[RTCP_TRANSPORT].reset(new IceContext(this, RTCP_TRANSPORT));
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                   functions for job with sdp message(answer, offer)

void AmRtpStream::getSdp(SdpMedia& m)
{
    m.is_multiplex = multiplexing;

    m.port = getLocalPort();
    m.rtcp_port = multiplexing ? 0 : getLocalRtcpPort();
    m.nports = 0;

    m.transport = transport;

    m.send = sending;
    m.recv = receiving;
    m.dir = SdpMedia::DirBoth;
}

void AmRtpStream::getSdpOffer(unsigned int index, SdpMedia& offer)
{
    CLASS_DBG("AmRtpStream::getSdpOffer(index = %u)",index);

    sdp_media_index = index;
    if(session) {
        auto session_trsp = session->getMediaTransport();
        if(session_trsp != TP_NONE) {
            transport = session_trsp;
        }

        if(!is_ice_stream)
            is_ice_stream = session->isUseIceMediaStream();
    }

    updateTransports();

    getSdp(offer);
    offer.payloads.clear();

    if(transport == TP_UDPTL || transport == TP_UDPTLSUDPTL) {
        cur_udptl_trans->getSdpOffer(offer);
    } else {
        payload_provider->getPayloads(offer.payloads);
        cur_rtp_trans->getSdpOffer(offer);
    }

    applyIceParams(offer);
}

void AmRtpStream::getSdpAnswer(unsigned int index, const SdpMedia& offer, SdpMedia& answer)
{
    CLASS_DBG("AmRtpStream::getSdpAnswer(index = %u)",index);

    if(offer.is_use_ice() && !AmConfig.enable_ice) {
        throw AmSession::Exception(488,"transport is not supported");
    }

    sdp_media_index = index;
    transport = offer.transport;
    is_ice_stream = offer.is_use_ice() &&
        (session ? session->isUseIceMediaStream() : false);

    updateTransports();

    getSdp(answer);
    offer.calcAnswer(payload_provider,answer);

    if(transport == TP_UDPTL || transport == TP_UDPTLSUDPTL) {
        cur_udptl_trans->getSdpAnswer(offer, answer);
    } else {
        cur_rtp_trans->getSdpAnswer(offer, answer);
    }

    applyIceParams(answer);
}

int AmRtpStream::init(const AmSdp& local,
    const AmSdp& remote,
    bool sdp_offer_owner,
    bool force_passive_mode)
{
    init_error.clear();
    if((sdp_media_index < 0) ||
       ((unsigned)sdp_media_index >= local.media.size()) ||
       ((unsigned)sdp_media_index >= remote.media.size())) {
        CLASS_ERROR("Media index %i is invalid, either within local or remote SDP (or both)",sdp_media_index);
        init_error = "Media index is invalid";
        return -1;
    }


    const SdpMedia& local_media = local.media[sdp_media_index];
    const SdpMedia& remote_media = remote.media[sdp_media_index];

    CLASS_DBG("AmRtpStream[%p]::init() sdp_media_index = %d, sdp_offer_owner = %d",
        this, sdp_media_index, sdp_offer_owner);

    if(local_media.type == MT_AUDIO) {
        payloads.clear();
        pl_map.clear();
        payloads.resize(local_media.payloads.size());

        int i=0;
        vector<SdpPayload>::const_iterator sdp_it = local_media.payloads.begin();
        vector<Payload>::iterator p_it = payloads.begin();

        // first pass on local SDP - fill pl_map with intersection of codecs
        while(sdp_it != local_media.payloads.end()) {
            int int_pt;

            bool isAllowTransport = (local_media.transport == TP_RTPAVP ||
                                     local_media.transport == TP_UDPTLSRTPSAVP ||
                                     local_media.transport == TP_RTPSAVP);
            if (isAllowTransport && sdp_it->payload_type < 20)
                int_pt = sdp_it->payload_type;
            else int_pt = payload_provider->getDynPayload(sdp_it->encoding_name,
                                                        sdp_it->clock_rate,
                                                        sdp_it->encoding_param);

            amci_payload_t* a_pl = NULL;
            if(int_pt >= 0)
                a_pl = payload_provider->payload(int_pt);

            if(a_pl == NULL) {
                if (relay_payloads.get(sdp_it->payload_type)) {
                    // this payload should be relayed, ignore
                    ++sdp_it;
                    continue;
                } else {
                    CLASS_DBG("No internal payload corresponding to type %s/%i (ignoring)",
                        sdp_it->encoding_name.c_str(),
                        sdp_it->clock_rate);
                    // ignore this payload
                    ++sdp_it;
                    continue;
                }
            }

            p_it->pt         = sdp_it->payload_type;
            p_it->name       = sdp_it->encoding_name;
            p_it->codec_id   = a_pl->codec_id;
            p_it->clock_rate = a_pl->sample_rate;
            p_it->advertised_clock_rate = sdp_it->clock_rate;

            pl_map[sdp_it->payload_type].index     = i;
            pl_map[sdp_it->payload_type].remote_pt = -1;

            ++p_it;
            ++sdp_it;
            ++i;
        } //while(sdp_it != local_media.payloads.end())

        // remove payloads which were not initialised (because of unknown payloads
        // which are to be relayed)
        if (p_it != payloads.end())
            payloads.erase(p_it, payloads.end());

        // second pass on remote SDP - initialize payload IDs used by remote (remote_pt)
        sdp_it = remote_media.payloads.begin();
        while(sdp_it != remote_media.payloads.end()) {

            // TODO: match not only on encoding name
            //       but also on parameters, if necessary
            //       Some codecs define multiple payloads
            //       with different encoding parameters
            PayloadMappingTable::iterator pmt_it = pl_map.end();
            bool isAllowTransport = (local_media.transport == TP_RTPAVP ||
                                     local_media.transport == TP_UDPTLSRTPSAVP ||
                                     local_media.transport == TP_RTPSAVP);
            if(sdp_it->encoding_name.empty() || (isAllowTransport && sdp_it->payload_type < 20))
            {
                // must be a static payload
                pmt_it = pl_map.find(sdp_it->payload_type);
            } else {
                for(p_it = payloads.begin(); p_it != payloads.end(); ++p_it) {
                    if(!strcasecmp(p_it->name.c_str(),sdp_it->encoding_name.c_str()) &&
                    (p_it->advertised_clock_rate == (unsigned int)sdp_it->clock_rate))
                    {
                        pmt_it = pl_map.find(p_it->pt);
                        break;
                    }
                }
            }

            // TODO: remove following code once proper
            //       payload matching is implemented
            //
            // initialize remote_pt if not already there
            if(pmt_it != pl_map.end() && (pmt_it->second.remote_pt < 0)) {
                pmt_it->second.remote_pt = sdp_it->payload_type;
            }
            ++sdp_it;
        } //while(sdp_it != remote_media.payloads.end())

        // set remote address - media c-line having precedence over session c-line
        if (remote.conn.address.empty() && remote_media.conn.address.empty()) {
            CLASS_WARN("no c= line given globally or in m= section in remote SDP");
            init_error = "no remote address";
            return -1;
        }

        if(local_media.payloads.empty()) {
            CLASS_DBG("local_media.payloads.empty()");
            init_error = "no payloads";
            return -1;
        }

        //find telephone-event intersections
        local_telephone_event_pt.reset(nullptr);
        remote_telephone_event_pt.reset(nullptr);
        for(auto const &remote_payload: remote_media.payloads) {
            if(remote_payload.encoding_name == "telephone-event") {
                for(auto const &local_payload: local_media.payloads) {
                    if(local_payload.encoding_name == "telephone-event"
                    && remote_payload.clock_rate == local_payload.clock_rate)
                    {
                        local_telephone_event_pt.reset(new SdpPayload(local_payload));
                        remote_telephone_event_pt.reset(new SdpPayload(remote_payload));
                        break;
                    }
                }
                if(local_telephone_event_pt.get()) //use first matched pair
                    break;
            }
        }

        //fill local telephone-event payloads bitset
        bzero(local_telephone_event_payloads, sizeof(local_telephone_event_payloads));
        for(auto const &p: local_media.payloads) {
            if(p.encoding_name == "telephone-event") {
                set_bit(p.payload_type % BITS_PER_LONG,
                        &local_telephone_event_payloads[p.payload_type >> _BITOPS_LONG_SHIFT]);
            }
        }

        if (remote_telephone_event_pt.get()) {
            CLASS_DBG("remote party supports telephone events (pt=%i)",
                remote_telephone_event_pt->payload_type);
        } else {
            CLASS_DBG("remote party doesn't support telephone events");
        }

        payload = getDefaultPT();
        if(payload < 0) {
            CLASS_DBG("could not set a default payload");
            init_error = "could not set a default payload";
            return -1;
        }
        CLASS_DBG("default payload selected = %i",payload);
        last_payload = payload;
    }

    CLASS_DBG("use transport = %d",
         local_media.transport);
    CLASS_DBG("local direction = %u, remote direction = %u",
         local_media.dir, remote_media.dir);
    CLASS_DBG("local setup = %u, remote setup = %u",
         local_media.setup, remote_media.setup);
#ifdef WITH_ZRTP
    CLASS_DBG("local media attribute: use_ice - %s, dtls - %s, srtp - %s, zrtp - %s",
#else/*WITH_ZRTP*/
    CLASS_DBG("local media attribute: use_ice - %s, dtls - %s, srtp - %s",
#endif/*WITH_ZRTP*/
         local_media.is_use_ice()?"true":"false",
         (local_media.is_dtls_srtp() || local_media.is_dtls_udptl())?"true":"false",
         (local_media.is_simple_srtp() || local_media.is_dtls_srtp() )?"true":"false"
#ifdef WITH_ZRTP
         , local_media.zrtp_hash.is_use?"true":"false");
#else/*WITH_ZRTP*/
         );
#endif/*WITH_ZRTP*/
#ifdef WITH_ZRTP
    CLASS_DBG("remote media attribute: use_ice - %s, dtls - %s, srtp - %s, zrtp - %s",
#else/*WITH_ZRTP*/
    CLASS_DBG("remote media attribute: use_ice - %s, dtls - %s, srtp - %s",
#endif/*WITH_ZRTP*/
         remote_media.is_use_ice()?"true":"false",
         (remote_media.is_dtls_srtp() || remote_media.is_dtls_udptl())?"true":"false",
         (remote_media.is_simple_srtp() || remote_media.is_dtls_srtp())?"true":"false"
#ifdef WITH_ZRTP
         , local_media.zrtp_hash.is_use?"true":"false");
#else/*WITH_ZRTP*/
         );
#endif/*WITH_ZRTP*/

    if((local_media.type == MT_AUDIO && !cur_rtp_trans) ||
       (local_media.type == MT_IMAGE && !cur_udptl_trans)) {
        CLASS_ERROR("AmRtpStream::init. failed to get transport");
        init_error = "failed to get transport";
        return -1;
    }

    if ((local_media.is_simple_srtp() && !remote_media.is_simple_srtp()) ||
        (local_media.is_dtls_srtp()  && !remote_media.is_dtls_srtp()) ||
        (local_media.is_simple_rtp()  && !remote_media.is_simple_rtp()) ||
        (local_media.is_dtls_udptl()  && !remote_media.is_dtls_udptl()) ||
        (local_media.is_udptl() && !remote_media.is_udptl())) {
        CLASS_ERROR("AmRtpStream::init. incompatible transport");
        init_error = "incompatible transport";
        return -1;
    }

    string address = remote_media.conn.address.empty() ?
        remote.conn.address : remote_media.conn.address;
    int port = static_cast<int>(remote_media.port);

    string rtcp_address = remote_media.rtcp_conn.address.empty() ?
        address : remote_media.rtcp_conn.address;
    int rtcp_port = static_cast<int>(remote_media.rtcp_port ?
        remote_media.rtcp_port : (multiplexing ? 0 : remote_media.port+1));

    bool connection_is_muted = false;
    try {
        {
            srtp_fingerprint_p fingerprint(remote_media.fingerprint.hash, remote_media.fingerprint.value);
            bool is_client = false;
            if(local_media.setup == S_ACTIVE || remote_media.setup == S_PASSIVE) is_client = true;
            else if(local_media.setup == S_PASSIVE || remote_media.setup == S_ACTIVE) is_client = false;

            if(local_media.is_dtls_srtp() && AmConfig.enable_srtp) {
                if(!dtls_context[RTP_TRANSPORT]) dtls_context[RTP_TRANSPORT].reset(new RtpSecureContext(this, fingerprint, is_client));
                if(!dtls_context[RTCP_TRANSPORT]) dtls_context[RTCP_TRANSPORT].reset(new RtpSecureContext(this, fingerprint, is_client));
            } else if(local_media.is_dtls_udptl() && cur_udptl_trans) {
                if(!dtls_context[FAX_TRANSPORT]) dtls_context[FAX_TRANSPORT].reset(new RtpSecureContext(this, fingerprint, is_client));
            }
        }
#ifdef WITH_ZRTP
        if(isZrtpEnabled() &&
           AmConfig.enable_srtp &&
           remote_media.zrtp_hash.is_use) {
            zrtp_context.setRemoteHash(remote_media.zrtp_hash.hash);
        }
#endif/*WITH_ZRTP*/

        AmMediaStateArgs args;

        if(remote_media.is_use_ice() && is_ice_stream) {
            initIce();
            bool need_restart = !(ice_remote_ufrag == remote_media.ice_ufrag &&
                                    ice_remote_pwd == remote_media.ice_pwd);
            if(need_restart) {
                ice_controlled = getSdpOfferOwner();
                ice_remote_ufrag = remote_media.ice_ufrag;
                ice_remote_pwd = remote_media.ice_pwd;

                getIceContext(RTP_TRANSPORT)->reset();
                if(!multiplexing)
                    getIceContext(RTCP_TRANSPORT)->reset();
            }
            iterateTransports([&](auto tr){
                CLASS_DBG("init ice stream:%p, state:%s", to_void(this), tr->state2str());
                auto conn_factory = tr->getConnFactory();
                args.candidates = &remote_media.ice_candidate;
                args.sdp_offer_owner = sdp_offer_owner;
                args.need_restart = need_restart;
                conn_factory->store_ice_cred(local_media, remote_media);

                // store srtp cred (sdes+srtp)
                if(tr->isSrtpEnable() && local_media.is_simple_srtp())
                    conn_factory->store_srtp_cred(local_media, remote_media);

                tr->template updateState<AmMediaIceState>(args);
            });
            getIceContext(RTP_TRANSPORT)->initContext();
            if(!multiplexing)
                getIceContext(RTCP_TRANSPORT)->initContext();
        } else if(local_media.is_simple_srtp() && AmConfig.enable_srtp) {
            MEDIA_interface& media_if = AmConfig.getMediaIfaceInfo(l_if);
            if(!media_if.srtp->srtp_enable)
                throw string("SRTP is not configured on: ") + media_if.name;

            args.address = address;
            args.port = port;

            CLASS_DBG("init srtp stream:%p, state:%s, type:%s",
                      to_void(this), cur_rtp_trans->state2str(), cur_rtp_trans->type2str());
            cur_rtp_trans->getConnFactory()->store_srtp_cred(local_media, remote_media);
            cur_rtp_trans->updateState<AmMediaSrtpState>(args);

            if(cur_rtcp_trans != cur_rtp_trans) {
                args.address = rtcp_address;
                args.port = rtcp_port;

                CLASS_DBG("init srtp stream:%p, state:%s, type:%s",
                          to_void(this), cur_rtcp_trans->state2str(), cur_rtcp_trans->type2str());

                cur_rtcp_trans->getConnFactory()->store_srtp_cred(local_media, remote_media);
                cur_rtcp_trans->updateState<AmMediaSrtpState>(args);
            }

            connection_is_muted = cur_rtp_trans->isMute(AmStreamConnection::RTP_CONN);
        } else if(local_media.is_dtls_srtp() && AmConfig.enable_srtp) {
            MEDIA_interface& media_if = AmConfig.getMediaIfaceInfo(l_if);
            if(!media_if.srtp->dtls_enable)
                throw string("DTLS is not configured on: ") + media_if.name;

            args.address = address;
            args.port = port;
            args.dtls_srtp = (local_media.is_dtls_srtp() && AmConfig.enable_srtp);

            CLASS_DBG("init dtls stream:%p, state:%s, type:%s", to_void(this),
                      cur_rtp_trans->state2str(), cur_rtp_trans->type2str());
            cur_rtp_trans->updateState<AmMediaDtlsState>(args);

            if(cur_rtcp_trans != cur_rtp_trans) {
                args.address = rtcp_address;
                args.port = rtcp_port;

                CLASS_DBG("init dtls stream:%p, state:%s, type:%s", to_void(this),
                          cur_rtcp_trans->state2str(), cur_rtcp_trans->type2str());
                cur_rtcp_trans->updateState<AmMediaDtlsState>(args);
            }

            connection_is_muted = cur_rtp_trans->isMute(AmStreamConnection::DTLS_CONN);
        } else if(local_media.transport == TP_UDPTL && cur_udptl_trans) {
            CLASS_DBG("init udptl stream:%p, state:%s, type:%s", to_void(this),
                      cur_udptl_trans->state2str(), cur_udptl_trans->type2str());

            args.address = address;
            args.port = port;
            args.udptl = true;
            cur_udptl_trans->updateState<AmMediaUdptlState>(args);

            connection_is_muted = cur_udptl_trans->isMute(AmStreamConnection::UDPTL_CONN);
        } else if(local_media.is_dtls_udptl() && cur_udptl_trans) {
            MEDIA_interface& media_if = AmConfig.getMediaIfaceInfo(l_if);
            if(!media_if.srtp->dtls_enable)
                throw string("DTLS is not configured on: ") + media_if.name;

            args.address = address;
            args.port = port;
            args.dtls_srtp = false;

            CLASS_DBG("init dtls stream:%p, state:%s, type:%s", to_void(this),
                      cur_udptl_trans->state2str(), cur_udptl_trans->type2str());
            cur_udptl_trans->updateState<AmMediaDtlsState>(args);

            connection_is_muted = cur_udptl_trans->isMute(AmStreamConnection::DTLS_CONN);
#ifdef WITH_ZRTP
        } else if(isZrtpEnabled() &&AmConfig.enable_srtp &&remote_media.zrtp_hash.is_use) {
            CLASS_DBG("init zrtp stream:%p, state:%s, type:%s", to_void(this),
                      cur_rtp_trans->state2str(), cur_rtp_trans->type2str());
            args.address = address;
            args.port = port;
            cur_rtp_trans->updateState<AmMediaZrtpState>(args);

            if(cur_rtcp_trans != cur_rtp_trans) {
                args.address = rtcp_address;
                args.port = rtcp_port;
                CLASS_DBG("init rtcp (%s, %d) stream:%p, state:%s, type:%s, cur_rtp_conn:%p",
                          address.data(), port, to_void(this),
                          cur_rtcp_trans->state2str(), cur_rtcp_trans->type2str(),
                          cur_rtcp_trans->getCurRtpConn());
                cur_rtcp_trans->updateState<AmMediaRtpState>(args);
            }

            connection_is_muted = cur_rtp_trans->isMute(AmStreamConnection::ZRTP_CONN);
#endif/*WITH_ZRTP*/
        } else {
            args.address = address;
            args.port = port;

            CLASS_DBG("init rtp (%s, %d) stream:%p, state:%s, type:%s, cur_rtp_conn:%p",
                      address.data(), port, to_void(this),
                      cur_rtp_trans->state2str(), cur_rtp_trans->type2str(),
                      cur_rtp_trans->getCurRtpConn());
            cur_rtp_trans->updateState<AmMediaRtpState>(args);

            if(cur_rtcp_trans != cur_rtp_trans) {
                args.address = rtcp_address;
                args.port = rtcp_port;
                CLASS_DBG("init rtcp (%s, %d) stream:%p, state:%s, type:%s, cur_rtp_conn:%p",
                          rtcp_address.data(), rtcp_port, to_void(this),
                          cur_rtcp_trans->state2str(), cur_rtcp_trans->type2str(),
                          cur_rtcp_trans->getCurRtpConn());
                cur_rtcp_trans->updateState<AmMediaRtpState>(args);
            }

            connection_is_muted = cur_rtp_trans->isMute(AmStreamConnection::RTP_CONN);
        }
    } catch(string& error) {
        log_demangled_stacktrace(L_ERR);
        CLASS_ERROR("Can't initialize connections. error - %s", error.c_str());
        init_error = error;
        return -1;
    }

    AmMediaTransport* rtptrans = cur_rtp_trans;
    if(transport == TP_UDPTL || transport == TP_UDPTLSUDPTL) rtptrans = cur_udptl_trans;

    rtptrans->setPassiveMode(remote_media.dir == SdpMedia::DirActive ||
                        remote_media.setup == S_ACTIVE ||
                        force_passive_mode);

    bool relay_is_muted = rtptrans->isMute(AmStreamConnection::RAW_CONN);
    sending = local_media.send;

    CLASS_DBG("local_recv:%d, local_send:%d, remote_recv:%d, remote_send:%d "
              "sending:%d remote_media.port:%u relay_is_muted:%d, conn_mute: %d",
        local_media.recv, local_media.send,
        remote_media.recv, remote_media.send,
        sending, remote_media.port, relay_is_muted, connection_is_muted);

    if(local_media.recv && remote_media.send) {
        resume();
    } else {
        pause();
    }

    sending = local_media.send;
    mute =
        (remote_media.port < 1024) ||   // fake ports see https://datatracker.ietf.org/doc/html/rfc2327 p.18
        relay_is_muted ||
        connection_is_muted;

    CLASS_DBG("mute = %d", mute);

    if(!timerisset(&rtp_stats.start))
        gettimeofday(&rtp_stats.start, nullptr);

    rtcp_reports.init(l_ssrc);

    last_not_supported_rx_payload = -1;
    last_not_supported_tx_payload = -1;

    active = false; // mark as nothing received yet

    return 0;
}

void AmRtpStream::updateTransports()
{
    if(transport == TP_UDPTL || transport == TP_UDPTLSUDPTL) {
        cur_udptl_trans->setTransportType(FAX_TRANSPORT);
    } else {
        cur_rtp_trans->setTransportType(RTP_TRANSPORT);
    }
}

void AmRtpStream::applyIceParams(SdpMedia& sdp_media)
{
    if(is_ice_stream) {
        initIP4Transport();
        initIP6Transport();

        sdp_media.is_ice = true;
        if(ice_pwd.empty()) {
            string data = AmSrtpConnection::gen_base64(ICE_PWD_SIZE);
            ice_pwd.clear();
            ice_pwd.append(data.begin(), data.begin() + ICE_PWD_SIZE);
        }
        sdp_media.ice_pwd = ice_pwd;
        if(ice_ufrag.empty()) {
            string data = AmSrtpConnection::gen_base64(ICE_UFRAG_SIZE);
            ice_ufrag.clear();
            ice_ufrag.append(data.begin(), data.begin() + ICE_UFRAG_SIZE);
        }
        sdp_media.ice_ufrag = ice_ufrag;
        iterateTransports([&](auto tr){
            SdpIceCandidate candidate;
            tr->prepareIceCandidate(candidate);
            tr->setIcePriority(candidate.priority);
            sdp_media.ice_candidate.push_back(candidate);
        });
    } else {
        sdp_media.is_ice = false;
        sdp_media.ice_pwd.clear();
        sdp_media.ice_ufrag.clear();
        sdp_media.ice_candidate.clear();
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                   transport callbacks functions(received RTP packets or transport errors)

void AmRtpStream::onErrorRtpTransport(AmStreamConnection::ConnectionError err, const string& error, AmMediaTransport* transport)
{
    struct sockaddr_storage laddr;
    transport->getLocalAddr(&laddr);
    if(err == AmStreamConnection::RTP_PARSER_ERROR) rtp_parse_errors++;
    else if(err == AmStreamConnection::SRTP_UNPROTECT_ERROR) srtp_unprotect_errors++;
    else {
        CLASS_DBG("%s (src_addr: %s:%i, "
            "local_ssrc: 0x%x, local_tag: %s)\n",
            error.c_str(),
            get_addr_str(&laddr).c_str(),am_get_port(&laddr),
            l_ssrc, getSessionLocalTag());
    }
}

void AmRtpStream::onRtpPacket(AmRtpPacket* p, AmMediaTransport* transport)
{
    int parse_res = RTP_PACKET_PARSE_OK;
    if(!relay_raw)
        parse_res = p->rtp_parse();

    struct sockaddr_storage laddr, raddr;
    p->getAddr(&raddr);
    transport->getLocalAddr(&laddr);
    if (parse_res == RTP_PACKET_PARSE_ERROR) {
        string error("error while parsing RTP packet. (src_addr: ");
        error += get_addr_str(&laddr) + ":" + int2str(am_get_port(&laddr)) + ", remote_addr: ";
        error += get_addr_str(&raddr) + ":" + int2str(am_get_port(&raddr)) + "local_ssrc: ";
        error += int2hexstr(l_ssrc) + ", local_tag: ";
        error += (session ? session->getLocalTag().c_str() : string("no session")) + ")";

        onErrorRtpTransport(AmStreamConnection::RTP_PARSER_ERROR, error, transport);

        clearRTPTimeout(&p->recv_time);
        freeRtpPacket(p);
    } else if(parse_res==RTP_PACKET_PARSE_OK) {
        bufferPacket(p);
        if(cur_rtp_trans != transport)
            cur_rtp_trans = transport;
    } else {
        CLASS_ERROR("error parsing: rtp packet is RTCP"
            "(src_addr: %s:%i, remote_addr: %s:%i, "
            "local_ssrc: 0x%x, local_tag: %s)\n",
            get_addr_str(&laddr).c_str(),am_get_port(&laddr),
            get_addr_str(&raddr).c_str(),am_get_port(&raddr),
            l_ssrc, getSessionLocalTag());
        freeRtpPacket(p);
        return;
    }
}

void AmRtpStream::onRtcpPacket(AmRtpPacket* p, AmMediaTransport* transport)
{
    p->rtcp_parse_update_stats(rtp_stats);
    if(cur_rtcp_trans != transport && multiplexing) {
        cur_rtcp_trans = transport;
    }
}

void AmRtpStream::onUdptlPacket(AmRtpPacket* p, AmMediaTransport*)
{
    clearRTPTimeout(&p->recv_time);
    AmLock l(receive_mut);
    if(!receive_buf.insert(ReceiveBuffer::value_type(p->timestamp,p)).second) {
        mem.freePacket(p);
    }
}

void AmRtpStream::onRawPacket(AmRtpPacket* p, AmMediaTransport*)
{
    if(!relay_raw)
        freeRtpPacket(p);
    bufferPacket(p);
}

void AmRtpStream::onSymmetricRtp()
{
    if(!symmetric_rtp_endless) {
        symmetric_rtp_enable = false;
    }
    if(!rtp_endpoint_learned_notified) {
        rtp_endpoint_learned_notified = true;
        if(session) session->onRtpEndpointLearned();
    }
}

bool AmRtpStream::isSymmetricRtpEnable()
{
    return symmetric_rtp_enable;
}

bool AmRtpStream::isSymmetricCandidateEnable()
{
    return is_ice_stream && symmetric_candidate_enable;
}

void AmRtpStream::allowStunConnection(AmMediaTransport* transport, sockaddr_storage* remote_addr, int priority)
{
    onSymmetricRtp();

    iterateTransports([&](auto tr){
        if(transport->getTransportType() != tr->getTransportType())
            return;
        tr->allowStunConnection(remote_addr, priority);
    });
    setCurrentTransport(getIceContext(transport->getTransportType())->getCurrentTransport());

    mute = cur_rtp_trans->isMute(AmStreamConnection::RAW_CONN);
}

void AmRtpStream::allowStunPair(AmMediaTransport* transport, sockaddr_storage* remote_addr)
{
    iterateTransports([&](auto tr){
        if(transport->getTransportType() != tr->getTransportType())
            return;
        tr->allowStunPair(remote_addr);
    });
    setCurrentTransport(transport);
}

void AmRtpStream::connectionTrafficDetected(AmMediaTransport* transport, sockaddr_storage* remote_addr)
{
    iterateTransports([&](auto tr){
        if(transport->getTransportType() != tr->getTransportType())
            return;
        tr->connectionTrafficDetected(remote_addr);
    });
    setCurrentTransport(transport);
}

void AmRtpStream::dtlsSessionActivated(AmMediaTransport* transport, uint16_t srtp_profile, const vector<uint8_t>& local_key, const vector<uint8_t>& remote_key)
{
    if(cur_rtp_trans != transport) {
        cur_rtp_trans = transport;
        if(multiplexing) {
            cur_rtcp_trans = transport;
        }
    }

    string l_key(local_key.size(), 0), r_key(remote_key.size(), 0);
    memcpy((void*)l_key.c_str(), local_key.data(), local_key.size());
    memcpy((void*)r_key.c_str(), remote_key.data(), remote_key.size());
    onSrtpKeysAvailable(transport->getTransportType(), srtp_profile, l_key, r_key);
}

void AmRtpStream::onIceRoleConflict()
{
    ice_controlled = !ice_controlled;
    ((uint32_t*)&ice_tiebreaker)[0] = get_random();
    ((uint32_t*)&ice_tiebreaker)[1] = get_random();
}

DtlsContext* AmRtpStream::getDtlsContext(uint8_t transport_type) {
    assert(transport_type < MAX_TRANSPORT_TYPE);
    if(transport_type == FAX_TRANSPORT && reuse_media_trans)
        transport_type = RTP_TRANSPORT;
    return dtls_context[transport_type].get();
}

IceContext * AmRtpStream::getIceContext(uint8_t transport_type)
{
    assert(transport_type < MAX_TRANSPORT_TYPE);
    if(transport_type == FAX_TRANSPORT && reuse_media_trans)
        transport_type = RTP_TRANSPORT;
    return ice_context[transport_type].get();
}

void AmRtpStream::initDtls(uint8_t transport_type, bool client)
{
    MEDIA_interface& media_if = AmConfig.getMediaIfaceInfo(l_if);
    if(!media_if.srtp->dtls_enable)
        throw string("DTLS is not configured on: ") + media_if.name;
    std::shared_ptr<dtls_conf> dtls_settings;
    if(client)
        dtls_settings = std::make_shared<dtls_conf>(&media_if.srtp->client_settings);
    else
        dtls_settings = std::make_shared<dtls_conf>(&media_if.srtp->server_settings);
    AmMediaTransport* transport = 0;
    if(transport_type == RTP_TRANSPORT)
        transport = cur_rtp_trans;
    else if(transport_type == RTCP_TRANSPORT)
        transport = cur_rtcp_trans;
    else
        transport = cur_udptl_trans;
    assert(transport);
    getDtlsContext(transport_type)->initContext(transport->getLocalIP(), transport->getLocalPort(), dtls_settings);
}

#ifdef WITH_ZRTP
extern "C" {
#include <bzrtp/bzrtp.h>
}

void AmRtpStream::zrtpSessionActivated(srtp_profile_t srtp_profile,
                                       const vector<uint8_t>& local_key,
                                       const vector<uint8_t>& remote_key)
{
    string l_key(local_key.size(), 0), r_key(remote_key.size(), 0);
    memcpy((void*)l_key.c_str(), local_key.data(), local_key.size());
    memcpy((void*)r_key.c_str(), remote_key.data(), remote_key.size());
    onSrtpKeysAvailable(RTP_TRANSPORT, srtp_profile, l_key, r_key);
}

void AmRtpStream::initZrtp()
{
    MEDIA_interface& media_if = AmConfig.getMediaIfaceInfo(l_if);
    zrtp_context.init(ZRTP_HASH_TYPE, media_if.srtp->zrtp_hashes);
    zrtp_context.init(ZRTP_CIPHERBLOCK_TYPE, media_if.srtp->zrtp_ciphers);
    zrtp_context.init(ZRTP_AUTHTAG_TYPE, media_if.srtp->zrtp_authtags);
    zrtp_context.init(ZRTP_KEYAGREEMENT_TYPE, media_if.srtp->zrtp_dhmodes);
    zrtp_context.init(ZRTP_SAS_TYPE, media_if.srtp->zrtp_sas);
    zrtp_context.start();
}

int AmRtpStream::send_zrtp(unsigned char* buffer, unsigned int size)
{
    if ((mute) || (!sending))
        return 0;

    AmRtpPacket rp;
    rp.compile_raw(buffer, size);
    sockaddr_storage raddr;
    cur_rtp_trans->getRAddr(false, &raddr);
    if(cur_rtp_trans && cur_rtp_trans->send(&raddr, buffer, size, AmStreamConnection::ZRTP_CONN) < 0) {
        CLASS_ERROR("while sending ZRTP packet.");
        return -1;
    }

    return size;
}

#endif/*WITH_ZRTP*/

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                   functions for job with RTP packets

AmRtpPacket * AmRtpStream::createRtpPacket()
{
    AmRtpPacket* p = mem.newPacket();
    if (!p) p = reuseBufferedPacket();
    if (!p) {
        out_of_buffer_errors++;
        receive_mut.lock();
        CLASS_DBG("out of buffers for RTP packets, dropping."
                "receive_buf: %ld, rtp_ev_qu: %ld",
                receive_buf.size(),rtp_ev_qu.size());
        mem.debug();
        receive_mut.unlock();
        // drop received data
        return 0;
    }

    return p;
}

void AmRtpStream::freeRtpPacket(AmRtpPacket* packet)
{
    assert(packet);
    mem.freePacket(packet);
}

// returns
// @param ts              [out] timestamp of the received packet,
//                              in audio buffer relative time
// @param audio_buffer_ts [in]  current ts at the audio_buffer

int AmRtpStream::receive(
    unsigned char* buffer, unsigned int size)
{
    AmRtpPacket* rp = NULL;
    int err = nextPacket(rp);

    if(err <= 0)
        return err;

    if (!rp)
        return 0;

    last_recv_relayed = rp->relayed;

    if(!last_recv_relayed) {
        /* do we have a new talk spurt? */
        begin_talk = ((last_payload == 13) || rp->marker);
        last_payload = last_recv_payload;

        add_if_no_exist(incoming_payloads[r_ssrc],rp->payload);
    }

    if(!rp->getDataSize()) {
        freeRtpPacket(rp);
        return RTP_EMPTY;
    }

    if(isLocalTelephoneEventPayload(rp->payload)) {
        if(!last_recv_relayed) recvDtmfPacket(rp);
        freeRtpPacket(rp);
        return RTP_DTMF;
    }

    assert(rp->getData());
    if(rp->getDataSize() > size) {
        CLASS_ERROR("received too big RTP packet");
        freeRtpPacket(rp);
        return RTP_BUFFER_SIZE;
    }

    memcpy(buffer,rp->getData(),rp->getDataSize());

    last_recv_ts = rp->timestamp;
    last_recv_payload = rp->payload;

    int res = rp->getDataSize();
    freeRtpPacket(rp);
    return res;
}

void AmRtpStream::bufferPacket(AmRtpPacket* p)
{
    clearRTPTimeout(&p->recv_time);
    update_receiver_stats(*p);

    if(!receiving) {
        if(force_receive_dtmf && isLocalTelephoneEventPayload(p->payload))
            recvDtmfPacket(p);
        mem.freePacket(p);
        return;
    }

    if (relay_enabled) {
        if (relay_raw ||
            /*(p->payload == getLocalTelephoneEventPT()
             && (force_relay_dtmf || !active)) ||*/
            //can relay
            (relay_payloads.get(p->payload) &&
             nullptr != relay_stream &&
             //check if actual remote payload mapping to local payload are equal
             p->payload == relay_map.get(
                static_cast<unsigned char>(relay_stream->getLastPayload()))) ||
            //force CN relay
            (force_relay_cn &&
             p->payload == COMFORT_NOISE_PAYLOAD_TYPE))
        {
            if(active) {
                CLASS_DBG("switching to relay-mode\t(ts=%u;stream=%p)",p->timestamp,this);
                active = false;
            }

            add_if_no_exist(incoming_relayed_payloads[r_ssrc],p->payload);

            if (NULL != relay_stream) //packet is not dtmf or relay dtmf is not filtered
            {
                relay_stream->relay(p);
                if(force_buffering && p->relayed) {
                    receive_mut.lock();
                    if(!receive_buf.insert(ReceiveBuffer::value_type(p->timestamp,p)).second) {
                        mem.freePacket(p);
                    }
                    receive_mut.unlock();
                    return;
                }
            }
            mem.freePacket(p);
            return;
        }
    } //if(relay_enabled)

    // throw away ZRTP packets
    if(p->version != RTP_VERSION) {
        mem.freePacket(p);
        return;
    }

    receive_mut.lock();
    // NOTE: useless, as DTMF events are pushed into 'rtp_ev_qu'
    // free packet on double packet for TS received
    // if(p->payload == getLocalTelephoneEventPT()) {
    //     if (receive_buf.find(p->timestamp) != receive_buf.end()) {
    //         mem.freePacket(receive_buf[p->timestamp]);
    //     }
    // }

    if(isLocalTelephoneEventPayload(p->payload)) {
        rtp_ev_qu.push(p);
    } else {
        if(!receive_buf.insert(ReceiveBuffer::value_type(p->timestamp,p)).second) {
            // insert failed
            mem.freePacket(p);
        }
    }
    receive_mut.unlock();
}

void AmRtpStream::recvDtmfPacket(AmRtpPacket* p)
{
    if(p->getDataSize()!=sizeof(dtmf_payload_t))
        return;
    auto dpl = reinterpret_cast<dtmf_payload_t*>(p->getData());
    /*CLASS_DBG("DTMF: event=%i; e=%i; r=%i; volume=%i; duration=%i; ts=%u session = [%p]",
                dpl->event,dpl->e,dpl->r,dpl->volume,ntohs(dpl->duration),p->timestamp, session);*/
    if(session)
        session->postDtmfEvent(new AmRtpDtmfEvent(dpl, getLocalTelephoneEventRate(), p->timestamp));
}

int AmRtpStream::nextPacket(AmRtpPacket*& p)
{
    //if (!receiving)
    // ignore 'passive' flag to avoid false RTP timeout for passive stream in sendonly mode
    if (!receiving)
        return RTP_EMPTY;

    struct timeval now;
    struct timeval diff;
    gettimeofday(&now,NULL);

    receive_mut.lock();
    timersub(&now,&last_recv_time,&diff);

    if(monitor_rtp_timeout &&
       dead_rtp_time &&
       sending &&
       (diff.tv_sec > 0) &&
       (static_cast<unsigned int>(diff.tv_sec) > dead_rtp_time))
    {
        CLASS_DBG("RTP Timeout detected. Last received packet is too old "
            "(diff.tv_sec = %i, limit = %i, "
            "local_ssrc: 0x%x, local_tag: %s)\n",
            static_cast<unsigned int>(diff.tv_sec),dead_rtp_time,
            l_ssrc, getSessionLocalTag());
        receive_mut.unlock();
        return RTP_TIMEOUT;
    }

    if(!rtp_ev_qu.empty()) {
        // first return RTP telephone event payloads
        p = rtp_ev_qu.front();
        rtp_ev_qu.pop();
        receive_mut.unlock();
        return 1;
    }

    if(receive_buf.empty()) {
        receive_mut.unlock();
        return RTP_EMPTY;
    }

    p = receive_buf.begin()->second;
    receive_buf.erase(receive_buf.begin());
    receive_mut.unlock();

    return 1;
}

AmRtpPacket *AmRtpStream::reuseBufferedPacket()
{
    AmRtpPacket *p = NULL;

    receive_mut.lock();
    if(!receive_buf.empty()) {
        p = receive_buf.begin()->second;
        receive_buf.erase(receive_buf.begin());
    }
    receive_mut.unlock();
    return p;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                   send functions
int AmRtpStream::send_udptl(unsigned int ts, unsigned char* buffer, unsigned int size)
{
    if ((mute) || (!sending))
        return 0;

    AmRtpPacket rp;
    rp.compile_raw(buffer, size);
    if(cur_udptl_trans && cur_udptl_trans->send(&rp, AmStreamConnection::UDPTL_CONN) < 0) {
        CLASS_ERROR("while sending RTP packet.");
        return -1;
    }

    return size;
}

int AmRtpStream::compile_and_send(
    const int payload, bool marker, unsigned int ts,
    unsigned char* buffer, unsigned int size)
{
    AmRtpPacket rp;
    rp.payload = payload;
    rp.timestamp = ts;
    rp.marker = marker;
    rp.sequence = sequence++;
    rp.ssrc = l_ssrc;
    rp.compile((unsigned char*)buffer,size);

    if(cur_rtp_trans && cur_rtp_trans->send(&rp, AmStreamConnection::RTP_CONN) < 0) {
        CLASS_ERROR("while sending RTP packet.");
        return -1;
    }

    add_if_no_exist(outgoing_payloads,rp.payload);
    outgoing_bytes+=rp.getDataSize();

    return size;
}

bool AmRtpStream::process_dtmf_queue(unsigned int ts)
{
    if(remote_telephone_event_pt.get() &&
       dtmf_sender.sendPacket(ts,remote_telephone_event_pt->payload_type,this))
    {
        return true;
    }
    return false;
}

unsigned int AmRtpStream::get_adjusted_ts(unsigned int ts)
{
    auto adjusted_ts = static_cast<decltype(tx_user_ts)>(ts+relay_ts_shift);
    auto ts_diff = tx_user_ts ? ts_unsigned_diff(adjusted_ts,tx_user_ts) : 0;

    /*CLASS_DBG("get_adjusted_ts(ts = %u) tx_user_ts = %llu",
              ts, tx_user_ts);*/

    if(ts_diff > RTP_TIMESTAMP_ALINGING_MAX_TS_DIFF) {
        CLASS_DBG("timestamp adjust condition reached: "
            "ts: %u, adjusted_ts: %llu, tx_user_ts: %llu, "
            "relay_ts_shift: %ld, ts_diff: %llu, "
            "max_ts_diff: %u",
            ts,adjusted_ts, tx_user_ts,
            relay_ts_shift,ts_diff,
            RTP_TIMESTAMP_ALINGING_MAX_TS_DIFF);

        auto old_ts_adjust = relay_ts_shift;

        relay_ts_shift = tx_user_ts - ts;

        CLASS_DBG("relay_ts_shift changed from %ld to %ld",
            old_ts_adjust,relay_ts_shift);

        adjusted_ts = static_cast<unsigned int>(ts+relay_ts_shift);
    }

    return adjusted_ts;
}

int AmRtpStream::send(unsigned int user_ts, unsigned char* buffer, unsigned int size)
{
    if ((mute) || (!sending))
        return 0;

    if(process_dtmf_queue(user_ts))
        return size;

    if(!size)
        return -1;

    if(payload == last_not_supported_tx_payload) {
        //attempt to send payload known as not supported. skip processing
        return 0;
    }

    auto it = pl_map.find(payload);
    if ((it == pl_map.end()) || (it->second.remote_pt < 0)) {
        CLASS_DBG("attempt to send packet with unsupported remote payload type %d", payload);
        last_not_supported_tx_payload = payload;
        return 0;
    }

    last_not_supported_tx_payload = -1;

    return compile_and_send(it->second.remote_pt, false, user_ts, buffer, size);
}

void AmRtpStream::relay(AmRtpPacket* p)
{
    // not yet initialized
    // or muted/on-hold
    if (mute || (!sending))
        return;

    if(!cur_rtp_trans) return;

    sockaddr_storage recv_addr;
    p->getAddr(&recv_addr);
    if(session && !session->onBeforeRTPRelay(p,&recv_addr))
        return;

    if(!relay_raw) {

        if(dtmf_sender.isSending())
            return;

        if(!tx_user_ts) {
            //no reference ts yet. skip sending
            return;
        }

        rtp_hdr_t* hdr = reinterpret_cast<rtp_hdr_t*>(p->getBuffer());

        if (!relay_transparent_seqno)
            hdr->seq = htons(sequence++);
        if (!relay_transparent_ssrc)
            hdr->ssrc = htonl(l_ssrc);

        hdr->pt = relay_map.get(hdr->pt);

        p->timestamp = get_adjusted_ts(p->timestamp);
        hdr->ts = htonl(p->timestamp);
    } //if(!relay_raw)

    if(cur_rtp_trans->send(p, relay_raw ? AmStreamConnection::RAW_CONN : AmStreamConnection::RTP_CONN) < 0) {
        CLASS_ERROR("while sending RTP packet to '%s':%i",
                    cur_rtp_trans->getRHost(false).c_str(),
                    cur_rtp_trans->getRPort(false));
    } else {
        p->relayed = true;
        if(session) {
            sockaddr_storage addr;
            if(relay_raw) {
                cur_rtp_trans->getRAddr(&addr);
            } else {
                cur_rtp_trans->getRAddr(false, &addr);
            }
            session->onAfterRTPRelay(p, &addr);
        }
        add_if_no_exist(outgoing_relayed_payloads,p->payload);
        outgoing_bytes += p->getBufferSize();
    }
}

void AmRtpStream::processRtcpTimers(unsigned long long system_ts, unsigned int user_ts)
{
    unsigned long long scaled_ts = system_ts/WALLCLOCK_RATE;

    if(!last_send_rtcp_report_ts) {
        last_send_rtcp_report_ts = scaled_ts;
    } else {
        if((scaled_ts - last_send_rtcp_report_ts) > RTCP_REPORT_SEND_INTERVAL_SECONDS) {
            last_send_rtcp_report_ts = scaled_ts;
            rtcp_send_report(user_ts);
        }
    }
}

void AmRtpStream::rtcp_send_report(unsigned int user_ts)
{
    void *buf;
    struct timeval now;
    unsigned int len;

    if(l_if < 0) return;

    gettimeofday(&now, nullptr);

    rtp_stats.lock();

    if(rtp_stats.tx.pkt) {
        if(rtp_stats.current_rx && rtp_stats.current_rx->pkt) {
            //SR with RR data
            fill_sender_report(rtcp_reports.sr.sr.sender,now,user_ts);
            fill_receiver_report(rtcp_reports.sr.sr.receiver, now);
            buf = &rtcp_reports.sr;
            len = sizeof(rtcp_reports.sr);
        } else {
            //SR without RR data
            fill_sender_report(rtcp_reports.sr_empty.sr.sender,now,user_ts);
            buf = &rtcp_reports.sr_empty;
            len = sizeof(rtcp_reports.sr_empty);
        }
   } else { //no data sent
        if(rtp_stats.current_rx && rtp_stats.current_rx->pkt) {
            //RR with data
            fill_receiver_report(rtcp_reports.rr.rr.receiver, now);
            buf = &rtcp_reports.rr;
            len = sizeof(rtcp_reports.rr);
        } else {
            //RR without data
            buf = &rtcp_reports.rr_empty;
            len = sizeof(rtcp_reports.rr_empty);
        }
    }

    rtp_stats.unlock();

    AmRtpPacket rp;
    rp.compile_raw((unsigned char*)buf,len);
    if(cur_rtcp_trans && cur_rtcp_trans->send(&rp, AmStreamConnection::RTCP_CONN) < 0) {
         CLASS_ERROR("failed to send RTCP packet: errno: %d, fd: %d, raddr: %s:%d, buf: %p:%d",
                     errno,
                     cur_rtcp_trans->getLocalSocket(),
                     cur_rtcp_trans->getRHost(true).c_str(),
                     cur_rtcp_trans->getRPort(true),
                     buf,len);
         return;
     }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                   functions for job with attributes

void AmRtpStream::setTransport(TransProt trans) {
    CLASS_DBG("set transport to: %d(%s)",trans, transport_p_2_str(trans).c_str());
    transport = trans;
}

void AmRtpStream::useIce()
{
    CLASS_DBG("set using ice protocol");
    is_ice_stream = true;
}

bool AmRtpStream::isIceStream()
{
    return is_ice_stream;
}

bool AmRtpStream::isIceControlled()
{
    return ice_controlled;
}

uint64_t AmRtpStream::getIceTieBreaker()
{
    return ice_tiebreaker;
}

void AmRtpStream::setMultiplexing(bool multiplex)
{
    CLASS_DBG("set using rtcp-mux %d -> %d", multiplexing, multiplex);
    multiplexing = multiplex;
}

void AmRtpStream::setReuseMediaPort(bool reuse_media)
{
    reuse_media_trans = reuse_media;
}

void AmRtpStream::clearRTPTimeout(struct timeval* recv_time)
{
    memcpy(&last_recv_time, recv_time, sizeof(struct timeval));
}

void AmRtpStream::clearRTPTimeout()
{
  gettimeofday(&last_recv_time,NULL);
}

int AmRtpStream::getDefaultPT()
{
    for(PayloadCollection::iterator it = payloads.begin();
        it != payloads.end(); ++it)
    {
        // skip telephone-events payload
        if(it->codec_id == CODEC_TELEPHONE_EVENT)
            continue;

        // skip incompatible payloads
        PayloadMappingTable::iterator pl_it = pl_map.find(it->pt);
        if ((pl_it == pl_map.end()) || (pl_it->second.remote_pt < 0))
            continue;
        return it->pt;
    }

    return -1;
}

int AmRtpStream::getLocalTelephoneEventRate()
{
    if (local_telephone_event_pt.get())
        return local_telephone_event_pt->clock_rate;
    return 0;
}

int AmRtpStream::getLocalTelephoneEventPT()
{
    if(local_telephone_event_pt.get())
        return local_telephone_event_pt->payload_type;
    return -1;
}

bool AmRtpStream::isLocalTelephoneEventPayload(unsigned char payload)
{
    return test_bit(
        payload % BITS_PER_LONG,
        &local_telephone_event_payloads[payload >> _BITOPS_LONG_SHIFT]);
}

void AmRtpStream::setPayloadProvider(AmPayloadProvider* pl_prov)
{
    payload_provider = pl_prov;
}

void AmRtpStream::setPassiveMode(bool p)
{
    if(p && !is_ice_stream)
        symmetric_rtp_enable = true;

    iterateTransports([&](auto tr){ tr->setPassiveMode(p); });
}

void AmRtpStream::setSymmetricCandidate(bool p)
{
    CLASS_DBG("set symmetric candidate=%s",p?"true":"false");
    symmetric_candidate_enable = p;
}

void AmRtpStream::setReceiving(bool r)
{
    CLASS_DBG("set receiving=%s",r?"true":"false");
    receiving = r;
}

void AmRtpStream::pause()
{
    CLASS_DBG("pausing (receiving=false)");
    receiving = false;
}

void AmRtpStream::resume()
{
    CLASS_DBG("resuming (receiving=true, clearing biffers/TS/TO)");

    clearRTPTimeout();

    receive_mut.lock();
    mem.clear();
    receive_buf.clear();
    while (!rtp_ev_qu.empty())
        rtp_ev_qu.pop();
    receive_mut.unlock();

    receiving = true;
}

void AmRtpStream::setOnHold(bool on_hold)
{
    CLASS_DBG("set hold %d", on_hold);
    sending = !on_hold;
}

bool AmRtpStream::getOnHold()
{
    return !sending;
}

void AmRtpStream::setMonitorRTPTimeout(bool m)
{
    monitor_rtp_timeout = m;
    CLASS_DBG("set RTP timeout monitoring to %d", m);
}

void AmRtpStream::setRelayStream(AmRtpStream* stream)
{
    relay_stream = stream;
    CLASS_DBG("set relay stream [%p]", stream);
}

void AmRtpStream::setRelayPayloads(const PayloadMask &_relay_payloads)
{
    relay_payloads = _relay_payloads;
}

void AmRtpStream::setRelayPayloadMap(const PayloadRelayMap & _relay_map)
{
    relay_map = _relay_map;
}

void AmRtpStream::enableRtpRelay()
{
    CLASS_DBG("enabled RTP relay");
    relay_enabled = true;
}

void AmRtpStream::disableRtpRelay()
{
    CLASS_DBG("disabled RTP relay");
    relay_enabled = false;
}

void AmRtpStream::setRawRelay(bool enable)
{
    CLASS_DBG("%sabled RAW relay", enable ? "en" : "dis");
    relay_raw = enable;
    if(cur_rtp_trans)
        cur_rtp_trans->setMode(AmMediaTransport::TRANSPORT_MODE_RAW);
}

bool AmRtpStream::isRawRelay()
{
    return relay_raw;
}

void AmRtpStream::setRtpRelayTransparentSeqno(bool transparent)
{
    CLASS_DBG("%sabled RTP relay transparent seqno",
        transparent ? "en":"dis");
    relay_transparent_seqno = transparent;
}

void AmRtpStream::setRtpRelayTransparentSSRC(bool transparent)
{
    CLASS_DBG("%sabled RTP relay transparent SSRC",
        transparent ? "en":"dis");
     relay_transparent_ssrc = transparent;
}

void AmRtpStream::setRtpRelayFilterRtpDtmf(bool filter)
{
    CLASS_DBG("%sabled RTP relay filtering of RTP DTMF (2833 / 3744)",
        filter ? "en":"dis");
    relay_filter_dtmf = filter;
}

void AmRtpStream::setRtpRelayTimestampAligning(bool enable_aligning)
{
    CLASS_DBG("%sabled RTP relay timestamp aligning",
        enable_aligning ? "en":"dis");
    relay_timestamp_aligning = enable_aligning;
    if(relay_timestamp_aligning) {
        CLASS_DBG("relay_timestamp_aligning is deprecated because of using timestamp from media processor as reference for relay");
    }
}

void AmRtpStream::setRtpForceRelayDtmf(bool relay)
{
    CLASS_DBG("%sabled force relay of RTP DTMF (2833 / 3744)",
        relay ? "en":"dis");
    force_relay_dtmf = relay;
}

void AmRtpStream::setRtpForceRelayCN(bool relay)
{
    CLASS_DBG("%sabled force relay CN payload",
        relay ? "en":"dis");
    force_relay_cn = relay;
}

void AmRtpStream::setSymmetricRtpEndless(bool endless)
{
    CLASS_DBG("%sabled endless symmetric RTP switching",
        endless ? "en":"dis");
    symmetric_rtp_endless = endless;
}

bool AmRtpStream::isSymmetricRtpEndless()
{
    return symmetric_rtp_endless;
}

bool AmRtpStream::isZrtpEnabled()
{
    return session ? session->isZrtpEnabled() : false;
}

void AmRtpStream::setRtpPing(bool enable)
{
    CLASS_DBG("%sabled RTP Ping", enable ? "en":"dis");
    rtp_ping = enable;
}

void AmRtpStream::setRtpTimeout(unsigned int timeout)
{
    dead_rtp_time = timeout;
    CLASS_DBG("set RTP dead time to %i", dead_rtp_time);
}

unsigned int AmRtpStream::getRtpTimeout()
{
    return dead_rtp_time;
}

string AmRtpStream::getPayloadName(int payload_type)
{
    for(PayloadCollection::iterator it = payloads.begin();
        it != payloads.end(); ++it)
    {
        if (it->pt == payload_type) return it->name;
    }
    return string("");
}

///
void AmRtpStream::stopReceiving()
{
    iterateTransports([](auto tr) { tr->stopReceiving(); });
}

void AmRtpStream::resumeReceiving()
{
    iterateTransports([](auto tr) { tr->resumeReceiving(); });
}

void AmRtpStream::setLogger(msg_logger* _logger)
{
    iterateTransports([&](auto tr) { tr->setLogger(_logger); });
}

void AmRtpStream::setSensor(msg_sensor *_sensor)
{
    CLASS_DBG("AmRtpStream: change sensor to %p",_sensor);
    iterateTransports([&](auto tr) { tr->setSensor(_sensor); });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                   help functions

void AmRtpStream::replaceAudioMediaParameters(SdpMedia &m, unsigned int idx, AddressType addr_type)
{
    setLocalIP(addr_type);

    if(m.port) //do not replace 0 port
        m.port = static_cast<unsigned int>(getLocalPort());

    //replace rtcp attribute
    m.rtcp_port = 0;
    m.rtcp_conn.address.clear();
    //DEPRECATED: because we perform 'rtcp' attr parsing
    //and store result in rtcp_port and rtcp_conn
    for(auto &a : m.attributes) {
        try {
            if (a.attribute == "rtcp") {
                RtcpAddress addr(a.value);
                addr.setPort(getLocalRtcpPort());
                if (addr.hasAddress()) addr.setAddress(getLocalIP());
                a.value = addr.print();
            }
        } catch (const std::exception &e) {
            DBG("can't replace RTCP address: %s", e.what());
        }
    }

    //ensure correct crypto parameters
    m.crypto.clear();
#ifdef WITH_ZRTP
    m.zrtp_hash.hash.clear();
    m.zrtp_hash.is_use = false;
#endif
    m.dir = SdpMedia::DirUndefined;
    m.setup = S_UNDEFINED;
    m.transport = transport;

    auto &dlg = session->dlg;
    if(!dlg) {
        CLASS_DBG("no dlg");
        return;
    }
    if(!cur_rtp_trans) {
        CLASS_DBG("no current RTP transport set");
        return;
    }

    switch(dlg->getOAState()) {
    case AmOfferAnswer::OA_None:
    case AmOfferAnswer::OA_OfferSent:
    case AmOfferAnswer::OA_Completed:
        cur_rtp_trans->getSdpOffer(m);
        break;
    case AmOfferAnswer::OA_OfferRecved: {
        const auto &offer = dlg->getRemoteSdp();
        if(idx >= offer.media.size()) {
            CLASS_DBG("no stream with idx %d in offer media", idx);
            return;
        }
        cur_rtp_trans->getSdpAnswer(offer.media[idx], m);
    } break;
    default:
        CLASS_ERROR("unexpected OA state %d in AmRtpStream::replaceAudioMediaParameters",
                    dlg->getOAState());
    }
}

void AmRtpStream::payloads_id2str(const vector<int> i, vector<string>& s)
{
    std::vector<int>::const_iterator it = i.begin();
    for(;it!=i.end();++it) {
        std::string pname;
        pname = getPayloadName(*it);
        if(pname.empty()) {
            if(*it==COMFORT_NOISE_PAYLOAD_TYPE)
                pname = "CN";
            else
                pname = int2str(*it);
        } else {
            transform(pname.begin(), pname.end(), pname.begin(), ::tolower);
        }
        s.push_back(pname);
    }
}

AmRtpStream::MediaStats::MediaStats()
  : time_start{0,0},
    time_end{0,0},
    dropped(0),
    out_of_buffer_errors(0),
    rtp_parse_errors(0),
    srtp_decript_errors(0),
    rtcp_rr_sent(0), rtcp_rr_recv(0),
    rtcp_sr_sent(0), rtcp_sr_recv(0)
{}

AmRtpStream::MediaStats::rtp_common::rtp_common()
  : ssrc(0),
    pkt(0),
    bytes(0),
    total_lost(0)
{
    bzero(&addr, sizeof(addr));
}

AmRtpStream::MediaStats::rx_stat::rx_stat()
  : decode_errors(0)
{}

void AmRtpStream::getMediaStats(MediaStats &s)
{
    auto &rx  = s.rx;
    auto &tx = s.tx;

    s.rtt = rtp_stats.rtt;
    s.dropped = dropped_packets_count;
    s.out_of_buffer_errors = out_of_buffer_errors;
    s.rtp_parse_errors = rtp_parse_errors;
    s.srtp_decript_errors = srtp_unprotect_errors;
    memcpy(&s.time_start, &rtp_stats.start, sizeof(struct timeval));
    gettimeofday(&s.time_end, nullptr);

    s.rtcp_rr_sent = rtp_stats.rtcp_rr_sent;
    s.rtcp_rr_recv = rtp_stats.rtcp_rr_recv;

    s.rtcp_sr_sent = rtp_stats.rtcp_sr_sent;
    s.rtcp_sr_recv = rtp_stats.rtcp_sr_recv;

    for(auto &it : rtp_stats.rx)
    {
        MediaStats::rx_stat* rx_ssrc;
        unsigned int ssrc = it.first;
        auto f_it = std::find_if(rx.begin(), rx.end(), [ssrc](const struct MediaStats::rx_stat& s)->bool{ return s.ssrc == ssrc; });
        if(f_it != rx.end())
            rx_ssrc = &*f_it;
        else {
            rx.emplace_back();
            rx_ssrc = &rx.back();
        }

        //RX rtp_common
        rx_ssrc->ssrc = ssrc;
        rx_ssrc->pkt = it.second.pkt;
        rx_ssrc->bytes = it.second.bytes;
        rx_ssrc->total_lost = it.second.loss;
        //RX specific
        rx_ssrc->rtcp_jitter = it.second.rtcp_jitter_usec;
        rx_ssrc->delta = it.second.rx_delta;
        rx_ssrc->jitter = it.second.jitter_usec;
        rx_ssrc->decode_errors = it.second.decode_err;
        memcpy(&rx_ssrc->addr, &it.second.addr, sizeof(struct sockaddr_storage));
        payloads_id2str(incoming_payloads[it.first],rx_ssrc->payloads_transcoded);
        payloads_id2str(incoming_relayed_payloads[it.first],rx_ssrc->payloads_relayed);
    }


    //TX rtp_comon
    tx.ssrc = l_ssrc;
    if(cur_rtp_trans) {
        cur_rtp_trans->getLocalAddr(&tx.addr);
    } else {
        memset(&tx.addr, 0, sizeof(struct sockaddr_storage));
    }
    tx.pkt = rtp_stats.tx.pkt;
    tx.bytes = rtp_stats.tx.bytes;
    tx.total_lost = rtp_stats.tx.loss;
    payloads_id2str(outgoing_payloads,tx.payloads_transcoded);
    payloads_id2str(outgoing_relayed_payloads,tx.payloads_relayed);

    //TX specific
    tx.jitter = rtp_stats.rtcp_remote_jitter;
}

void AmRtpStream::getMediaAcl(trsp_acl& acl)
{
    if(session)
        session->getMediaAcl(acl);
}

bool AmRtpStream::getSdpOfferOwner()
{
    if(session) session->getSdpOfferOwner();
    return false;
}

void AmRtpStream::debug()
{
#define BOOL_STR(b) ((b) ? "yes" : "no")

    if(cur_rtp_trans) {
        CLASS_DBG("\t<%i> <-> <%s:%i>", getLocalPort(),
            getRHost(false).c_str(), cur_rtp_trans->getRPort(false));
    } else {
        CLASS_DBG("\t<unbound> <-> <%s:%i>",
            getRHost(false).c_str(), getLocalPort());
    }

    if (relay_enabled && relay_stream) {
        CLASS_DBG("\tinternal relay to stream %p (local port %i)",
            relay_stream, relay_stream->getLocalPort());
    } else {
        CLASS_DBG("\tno relay");
    }

    CLASS_DBG("\tmute: %s, sending: %s, receiving: %s",
        BOOL_STR(mute), BOOL_STR(sending), BOOL_STR(receiving));
#undef BOOL_STR
}

void AmRtpStream::getInfo(AmArg &ret){
    std::stringstream s;
    s << std::hex << this;
    ret["self_ptr"] = s.str();

    s.clear();
    ret["relay_enabled"] = relay_enabled;
    ret["relay_raw"] = relay_raw;
    ret["force_relay_cn"] = force_relay_cn;
    AmArg &p = ret["relay_payloads"];
    for(auto& payload : payloads) {
        if(relay_payloads.get(payload.pt)) {
            AmArg pl;
            pl["encoding_name"] = payload.name;
            pl["payload_type"] = payload.pt;
            pl["clock_rate"] = (int)payload.clock_rate;
            p.push(pl);
        }
    }
    if(relay_stream) {
        std::stringstream s;
        s << std::hex << relay_stream;
        ret["relay_ptr"] = s.str();
    } else {
        ret["relay_ptr"] = "nullptr";
    }

    ret["sdp_media_index"] = sdp_media_index;
    ret["l_ssrc"] = int2hex(l_ssrc);

    if(cur_rtp_trans) {
        AmArg &a = ret["socket"];
        a["local_ip"] = cur_rtp_trans->getLocalIP();
        a["local_port"] = getLocalPort();
        a["remote_host"] = getRHost(RTP_TRANSPORT);
        a["remote_port"] = getRPort(RTP_TRANSPORT);
    } else {
        ret["socket"] = "unbound";
    }

    ret["mute"] = mute;
    ret["sending"] = sending;
    ret["receiving"] = receiving;

    AmArg& transports = ret["transports"];
    for(auto& transport: ip4_transports) {
        AmArg trsp;
        trsp["protocol"] = "ip4";
        transport->getInfo(trsp);
        transports.push(trsp);
    }
    for(auto& transport: ip6_transports) {
        AmArg trsp;
        trsp["protocol"] = "ip6";
        transport->getInfo(trsp);
        transports.push(trsp);
    }
}

const char *AmRtpStream::getSessionLocalTag() const
{
    if(session)
        return session->getLocalTag().data();
    return "null";
}

void AmRtpStream::update_sender_stats(const AmRtpPacket &p)
{
    AmLock l(rtp_stats);

    //struct timeval now;

    //gettimeofday(&now, nullptr);

    rtp_stats.rtp_tx_last_ts = p.timestamp;
    rtp_stats.rtp_tx_last_seq = p.sequence;

    RtcpUnidirectionalStat &s = rtp_stats.tx;

    //s.update = now;
    //s.update_cnt++;

    s.pkt++;
    s.bytes += p.getDataSize();
}

void AmRtpStream::fill_sender_report(RtcpSenderReportHeader &s, struct timeval &now, unsigned int user_ts)
{
    uint64_t i;

    rtp_stats.rtcp_sr_sent++;

    s.sender_pcount = htonl(rtp_stats.tx.pkt);
    s.sender_bcount = htonl(rtp_stats.tx.bytes);
    s.rtp_ts = htonl(user_ts);

    i = now.tv_usec;
    i <<= 32;
    i /= 1000000;
    s.ntp_frac = htonl(i);

    i = now.tv_sec;
    i += NTP_TIME_OFFSET;
    s.ntp_sec = htonl(i);
}

void AmRtpStream::init_receiver_info(const AmRtpPacket &p)
{
    r_ssrc = p.ssrc;
    rtcp_reports.update(r_ssrc);
    r_ssrc_i = true;

    rtp_stats.probation = MIN_SEQUENTIAL;
    rtp_stats.init_seq(p.ssrc, p.sequence);
}

void AmRtpStream::update_receiver_stats(const AmRtpPacket &p)
{
    AmLock l(rtp_stats);

    if((!r_ssrc_i) || (p.ssrc!=r_ssrc)) {
        if(rtp_stats.current_rx)
            rtp_stats.current_rx->loss += rtp_stats.total_lost;
        init_receiver_info(p);
    }

    if(rtp_stats.current_rx) {
        memccpy(&rtp_stats.current_rx->addr, &p.saddr, 1, sizeof(struct sockaddr_storage));
        rtp_stats.current_rx->pkt++;
        rtp_stats.current_rx->bytes += p.getDataSize();
    }

    if(!rtp_stats.update_seq(p.ssrc, p.sequence)) {
        /* skip jitter measurement
           for duplicated/reordered/unexpected sequence packets */
        return;
    }

    //https://tools.ietf.org/html/rfc3550#appendix-A.8
    uint64_t recv_time_msec = p.recv_time.tv_sec*1000 + p.recv_time.tv_usec/1000;
    int transit = (recv_time_msec << 3) - p.timestamp;
    if(rtp_stats.transit) {
        int d = rtp_stats.transit - transit;
        if(d < 0) d = -d;
        if(rtp_stats.current_rx) rtp_stats.current_rx->rtcp_jitter += d - ((rtp_stats.current_rx->rtcp_jitter + 8) >> 4);
    }
    rtp_stats.transit = transit;

    if(timerisset(&rtp_stats.rx_recv_time)) {
        timeval diff;
        timersub(&p.recv_time, &rtp_stats.rx_recv_time, &diff);
        if(rtp_stats.current_rx) {
            auto &rx_delta = rtp_stats.current_rx->rx_delta;
            rx_delta.update((diff.tv_sec * 1000000) + diff.tv_usec);
            if(rx_delta.n && (0 == rx_delta.n % 250)) {
                //update jitter every 250 packets (5 seconds)
                rtp_stats.current_rx->jitter_usec.update(rx_delta.sd());
            }
        }
    }
    rtp_stats.rx_recv_time = p.recv_time;
}

void AmRtpStream::fill_receiver_report(RtcpReceiverReportHeader &r, struct timeval &now)
{
    struct timeval delay;

    rtp_stats.rtcp_rr_sent++;

    rtp_stats.update_lost();

    r.total_lost_2 = (rtp_stats.total_lost >> 16) & 0xff;
    r.total_lost_1 = (rtp_stats.total_lost >> 8) & 0xff;
    r.total_lost_0 = rtp_stats.total_lost & 0xff;

    r.fract_lost = rtp_stats.fraction_lost;

    r.last_seq = ((rtp_stats.cycles << 16) | (rtp_stats.max_seq & 0xffff));
    r.last_seq = htonl(r.last_seq);

    if(rtp_stats.sr_lsr) {
        r.lsr = htonl(rtp_stats.sr_lsr);

        timersub(&now,&rtp_stats.sr_recv_time,&delay);
        r.dlsr = (delay.tv_sec << 16);
        r.dlsr |= (uint16_t)(delay.tv_usec*65536/1e6);
        r.dlsr = htonl(r.dlsr);
    } else {
        r.lsr = 0;
        r.dlsr = 0;
    }

    uint32_t jitter = rtp_stats.current_rx->rtcp_jitter >> 4;
    r.jitter = htonl(jitter);

    //update stats
    rtp_stats.current_rx->rtcp_jitter_usec.update(jitter);
}

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
#include "AmSrtpConnection.h"
#include "AmRtpPacket.h"
#include "AmRtpReceiver.h"
#include "AmLcConfig.h"
#include "AmPlugIn.h"
#include "AmAudio.h"
#include "AmUtils.h"
#include "AmSession.h"

#include "AmDtmfDetector.h"
#include "rtp/telephone_event.h"
#include "amci/codecs.h"
#include "AmJitterBuffer.h"

#include "sip/resolver.h"
#include "sip/ip_util.h"
#include "sip/transport.h"
#include "sip/raw_sender.h"
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
#include "AmDtlsConnection.h"
#include "AmStunConnection.h"

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
  : l_if(_if),
    r_ssrc_i(false),
    session(_s),
    offer_answer_used(true),
    active(false), // do not return any data unless something really received
    multiplexing(false),
    mute(false),
    hold(false),
    receiving(true),
    monitor_rtp_timeout(true),
    symmetric_rtp_endless(false),
    relay_stream(NULL),
    relay_enabled(false),
    relay_raw(false),
    sdp_media_index(-1),
    last_recv_payload(-1),
    last_recv_relayed(false),
    last_recv_ts(0),
    relay_transparent_ssrc(false),
    relay_transparent_seqno(false),
    relay_filter_dtmf(false),
    force_relay_dtmf(true),
    relay_timestamp_aligning(false),
    force_receive_dtmf(false),
    rtp_ping(false),
    force_buffering(false),
    dead_rtp_time(AmConfig.dead_rtp_time),
    incoming_bytes(0),
    outgoing_bytes(0),
    dropped_packets_count(0),
    decode_errors(0),
    rtp_parse_errors(0),
    srtp_unprotect_errors(0),
    out_of_buffer_errors(0),
    wrong_payload_errors(0),
    not_supported_rx_payload_local_reported(false),
    not_supported_rx_payload_remote_reported(false),
    not_supported_tx_payload_reported(false),
    relay_ts_shift(0),
    tx_user_ts(0),
    last_send_rtcp_report_ts(0),
    transport(TP_RTPAVP),
    is_ice_stream(false),
    reuse_media_trans(true),
    cur_rtp_trans(0),
    cur_rtcp_trans(0),
    cur_udptl_trans(0)
{
    DBG("AmRtpStream[%p](%p)",this,session);

    l_ssrc = get_random();
    sequence = get_random();
    clearRTPTimeout();
    memcpy(&start_time, &last_recv_time, sizeof(struct timeval));

    // by default the system codecs
    payload_provider = AmPlugIn::instance();
#ifdef WITH_ZRTP
    zrtp_context.addSubscriber(this);
#endif/*WITH_ZRTP*/

    bzero(local_telephone_event_payloads, sizeof(local_telephone_event_payloads));

    if(_s) {
        multiplexing = _s->isRtcpMultiplexing();
    }
}

AmRtpStream::~AmRtpStream()
{
    DBG("~AmRtpStream[%p]() session = %p",this,session);
    if(session) session->onRTPStreamDestroy(this);
    for(auto trans : ip4_transports) {
        delete trans;
    }
    for(auto trans : ip6_transports) {
        delete trans;
    }
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

void AmRtpStream::setLocalIP(const string& host)
{
    CLASS_DBG("host = %s\n",host.data());

    sockaddr_storage addr;
    dns_handle dh;

    if (resolver::instance()->resolve_name(host.data(),&dh,&addr, Dualstack) < 0) {
        throw string ("AmRtpStream::setLocalIP: failed to resolve local IP address: ") + host;
    }

    if(l_if < 0) {
        if (session) l_if = session->getRtpInterface();
        else {
            CLASS_ERROR("BUG: no session when initializing RTP stream, invalid interface can be used\n");
            l_if = 0;
        }
    }

    vector<AmMediaTransport*>* transports;
    if(addr.ss_family == AF_INET) {
        initIP4Transport();
        transports = &ip4_transports;
    } else {
        initIP6Transport();
        transports = &ip6_transports;
    }

    int count = 1;

    for(auto transport : *transports) {
        if(count == RTP_TRANSPORT) {
            CLASS_DBG("set current rtp transport %p", transport);
            cur_rtp_trans = transport;
            count++;
            if(multiplexing) count++;
            continue;
        }

        if(count == FAX_TRANSPORT) {
            CLASS_DBG("set current udptl transport %p", transport);
            cur_udptl_trans = transport;
            count++;
            continue;
        }

        if(count == RTCP_TRANSPORT) {
            CLASS_DBG("set current rtcp transport %p", transport);
            cur_rtcp_trans = transport;
            count++;
            continue;
        }
    }

    if(!cur_rtp_trans) {
        throw string("AmRtpStream:setLocalIP. failed to get transport");
    }

    if(!cur_rtcp_trans) {
        cur_rtcp_trans = cur_rtp_trans;
    }

    if(!cur_udptl_trans) {
        cur_udptl_trans = cur_rtp_trans;
    }
}

int AmRtpStream::getLocalPort()
{
    if(!cur_rtp_trans || !cur_rtcp_trans || !cur_udptl_trans) {
        setLocalIP(session->advertisedIP());
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
        setLocalIP(session->advertisedIP());
    }

    if(!cur_rtp_trans || !cur_rtcp_trans || !cur_udptl_trans) {
        ERROR("AmRtpStream:getLocalRtcpPort. failed to get transport");
        return 0;
    }

    return cur_rtcp_trans->getLocalPort();
}

void AmRtpStream::calcRtpPorts(AmMediaTransport* tr_rtp, AmMediaTransport* tr_rtcp)
{
    if(tr_rtp->getLocalPort() && tr_rtcp && tr_rtcp->getLocalPort())
        return;

    int retry = BIND_ATTEMPTS_COUNT;
    unsigned short port = 0;

    assert(tr_rtp);

    for(;retry; --retry) {

        if (!tr_rtp->getLocalSocket() || (tr_rtcp && !tr_rtcp->getLocalSocket()))
            return;

        port = AmConfig.getMediaProtoInfo(tr_rtp->getLocalIf(),
                                          tr_rtp->getLocalProtoId()).getNextRtpPort();

        if(!port) {
            retry = 0;
            break;
        }

        sockaddr_storage l_rtcp_addr, l_rtp_addr;
        if(tr_rtp != tr_rtcp && tr_rtcp) {
            tr_rtcp->getLocalAddr(&l_rtcp_addr);
            am_set_port(&l_rtcp_addr,port+1);
            if(bind(tr_rtcp->getLocalSocket(),(const struct sockaddr*)&l_rtcp_addr,SA_len(&l_rtcp_addr))) {
                CLASS_ERROR("failed to bind port %hu for RTCP: %s\n",
                          port+1, strerror(errno));
                goto try_another_port;
            }
        }

        tr_rtp->getLocalAddr(&l_rtp_addr);
        am_set_port(&l_rtp_addr,port);
        if(bind(tr_rtp->getLocalSocket(),(const struct sockaddr*)&l_rtp_addr,SA_len(&l_rtp_addr))) {
            CLASS_ERROR("failed to bind port %hu for RTP: %s\n",
                        port, strerror(errno));
            goto try_another_port;
        }

        // both bind() succeeded!
        break;

try_another_port:
        AmConfig.getMediaProtoInfo(tr_rtp->getLocalIf(),
                                   tr_rtp->getLocalProtoId()).freeRtpPort(port);

        tr_rtp->getLocalSocket(true);
        if(tr_rtp != tr_rtcp && tr_rtcp) {
            tr_rtcp->getLocalSocket(true);
        }
    }

    if (!retry) {
        ERROR("could not bind RTP/RTCP ports considered free after %d attempts",
              BIND_ATTEMPTS_COUNT);
        throw string("could not find a free RTP port\n");
    }

    // rco: does that make sense after bind() ????
    tr_rtp->setLocalPort(port);
    if(tr_rtp != tr_rtcp && tr_rtcp) {
        tr_rtcp->setLocalPort(port + 1);
    }
}

void AmRtpStream::setRAddr(const string& addr, unsigned short port)
{
    CLASS_DBG("RTP remote address set to %s:%u\n", addr.c_str(),port);
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
        mute = cur_transport->isMute();
    }
}

void AmRtpStream::addAdditionTransport()
{
    if(reuse_media_trans) {
        return;
    }

    if(!cur_rtp_trans || !cur_rtcp_trans || !cur_udptl_trans) {
        setLocalIP(session->advertisedIP());
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
        CLASS_DBG("AmRtpTransport: missed requested %s proto in choosen media interface %d", type == AT_V4 ? "ipv4" : "ipv6", l_if);
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
        CLASS_DBG("AmRtpTransport: missed requested ipv4 proto in choosen media interface %d", l_if);
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
        CLASS_DBG("AmRtpTransport: missed requested ipv6 proto in choosen media interface %d", l_if);
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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                   functions for job with sdp message(answer, offer)

void AmRtpStream::getSdp(SdpMedia& m)
{
    m.port = getLocalPort();
    m.nports = 0;
    m.transport = transport;
    m.send = !hold;
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
    offer.is_multiplex = multiplexing;
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
    is_ice_stream = offer.is_use_ice();
    answer.rtcp_port = getLocalRtcpPort();
    answer.is_multiplex = multiplexing;

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

    CLASS_DBG("AmRtpStream[%p]::init() sdp_media_index = %d",this,sdp_media_index);

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

            if ((local_media.transport == TP_RTPAVP ||
                local_media.transport == TP_UDPTLSRTPSAVP ||
                local_media.transport == TP_RTPSAVP) && sdp_it->payload_type < 20)
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
                    CLASS_DBG("No internal payload corresponding to type %s/%i (ignoring)\n",
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
            if(sdp_it->encoding_name.empty() || (local_media.transport == TP_RTPAVP && sdp_it->payload_type < 20))
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
            CLASS_WARN("no c= line given globally or in m= section in remote SDP\n");
            init_error = "no remote address";
            return -1;
        }

        if(local_media.payloads.empty()) {
            CLASS_DBG("local_media.payloads.empty()\n");
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
            CLASS_DBG("remote party supports telephone events (pt=%i)\n",
                remote_telephone_event_pt->payload_type);
        } else {
            CLASS_DBG("remote party doesn't support telephone events\n");
        }

        payload = getDefaultPT();
        if(payload < 0) {
            CLASS_DBG("could not set a default payload\n");
            init_error = "could not set a default payload";
            return -1;
        }
        CLASS_DBG("default payload selected = %i\n",payload);
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

    try {
        if(remote_media.is_use_ice()) {
            for(auto transport : ip4_transports) {
                transport->initIceConnection(local_media, remote_media);
            }
            for(auto transport : ip6_transports) {
                transport->initIceConnection(local_media, remote_media);
            }
        } else if(local_media.is_simple_srtp() && AmConfig.enable_srtp) {
            cur_rtp_trans->initSrtpConnection(address, port, local_media, remote_media);
            if(cur_rtcp_trans != cur_rtp_trans)
                cur_rtcp_trans->initSrtpConnection(rtcp_address, rtcp_port, local_media, remote_media);
        } else if(local_media.is_dtls_srtp() && AmConfig.enable_srtp) {
            cur_rtp_trans->initDtlsConnection(address, port, local_media, remote_media);
            if(cur_rtcp_trans != cur_rtp_trans)
                cur_rtcp_trans->initDtlsConnection(rtcp_address, rtcp_port, local_media, remote_media);
        } else if(local_media.transport == TP_UDPTL && cur_udptl_trans) {
            cur_udptl_trans->initUdptlConnection(address, port);
        } else if(local_media.is_dtls_udptl() && cur_udptl_trans) {
            cur_udptl_trans->initDtlsConnection(address, port, local_media, remote_media);
            cur_udptl_trans->initUdptlConnection(address, port);
#ifdef WITH_ZRTP
        } else if(session && session->isZrtpEnabled() && AmConfig.enable_srtp) {
                if(remote_media.zrtp_hash.is_use) {
                    zrtp_context.setRemoteHash(remote_media.zrtp_hash.hash);
                }
                cur_rtp_trans->initZrtpConnection(address, port);
                if(cur_rtcp_trans != cur_rtp_trans)
                    cur_rtcp_trans->initRtpConnection(address, port);

                RTP_info* rtpinfo = RTP_info::toMEDIA_RTP(
                    &AmConfig.getMediaProtoInfo(cur_rtp_trans->getLocalIf(), cur_rtp_trans->getLocalProtoId()));
                zrtp_context.init(ZRTP_HASH_TYPE, rtpinfo->zrtp_hashes);
                zrtp_context.init(ZRTP_CIPHERBLOCK_TYPE, rtpinfo->zrtp_ciphers);
                zrtp_context.init(ZRTP_AUTHTAG_TYPE, rtpinfo->zrtp_authtags);
                zrtp_context.init(ZRTP_KEYAGREEMENT_TYPE, rtpinfo->zrtp_dhmodes);
                zrtp_context.init(ZRTP_SAS_TYPE, rtpinfo->zrtp_sas);
                zrtp_context.start();
#endif/*WITH_ZRTP*/
        } else {
            cur_rtp_trans->initRtpConnection(address, port);
            if(cur_rtcp_trans != cur_rtp_trans) {
                cur_rtcp_trans->initRtpConnection(rtcp_address, rtcp_port);
            }
        }
    } catch(string& error) {
        CLASS_ERROR("Can't initialize connections. error - %s", error.c_str());
        init_error = error;
        return -1;
    }

    AmMediaTransport* rtptrans = cur_rtp_trans;
    if(transport == TP_UDPTL || transport == TP_UDPTLSUDPTL) rtptrans = cur_udptl_trans;

    rtptrans->setPassiveMode(remote_media.dir == SdpMedia::DirActive ||
                        remote_media.setup == S_ACTIVE ||
                        force_passive_mode);

    CLASS_DBG("recv = %d, send = %d",
        local_media.recv, local_media.send);

    if(local_media.recv) {
        resume();
    } else {
        pause();
    }

    sockaddr_storage raddr;
    rtptrans->getRAddr(false, &raddr);
    if(local_media.send && !hold &&
       (remote_media.port != 0) &&
       !rtptrans->isMute())
     {
         mute = false;
     } else {
         mute = true;
     }
     CLASS_DBG("mute = %d",mute);

    gettimeofday(&rtp_stats.start, nullptr);
    rtcp_reports.init(l_ssrc);


    active = false; // mark as nothing received yet

    return 0;
}

void AmRtpStream::updateTransports()
{
    if(transport == TP_UDPTL || transport == TP_UDPTLSUDPTL) {
        cur_udptl_trans->setTransportType(FAX_TRANSPORT);
    } else {
        cur_rtp_trans->setTransportType(RTP_TRANSPORT);
        if(cur_rtp_trans != cur_rtcp_trans)
            cur_rtcp_trans->setTransportType(RTCP_TRANSPORT);
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
        for(auto transport : ip4_transports) {
            transport->getIceCandidate(sdp_media);
        }
        for(auto transport : ip6_transports) {
            transport->getIceCandidate(sdp_media);
        }
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
        CLASS_ERROR("%s (src_addr: %s:%i, "
                "local_ssrc: 0x%x, local_tag: %s)\n",
                error.c_str(),
                get_addr_str(&laddr).c_str(),am_get_port(&laddr),
                l_ssrc,session ? session->getLocalTag().c_str() : "no session");
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
    } else {
        CLASS_ERROR("error parsing: rtp packet is RTCP"
            "(src_addr: %s:%i, remote_addr: %s:%i, "
            "local_ssrc: 0x%x, local_tag: %s)\n",
            get_addr_str(&laddr).c_str(),am_get_port(&laddr),
            get_addr_str(&raddr).c_str(),am_get_port(&raddr),
            l_ssrc,session ? session->getLocalTag().c_str() : "no session");
        freeRtpPacket(p);
        return;
    }
}

void AmRtpStream::onRtcpPacket(AmRtpPacket* p, AmMediaTransport*)
{
    p->rtcp_parse_update_stats(rtp_stats);
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

void AmRtpStream::allowStunConnection(AmMediaTransport* transport, int priority)
{
    if(transport->getTransportType() == RTP_TRANSPORT) {
        cur_rtp_trans = transport;
        if(!cur_rtcp_trans && multiplexing) {
            cur_rtcp_trans = transport;
        }
    } else if(transport->getTransportType() == RTCP_TRANSPORT) {
        cur_rtcp_trans = transport;
    }

    for(auto tr : ip4_transports) {
        if(transport->getTransportType() == tr->getTransportType()) {
            tr->updateStunTimers();
        }
    }
    for(auto tr : ip6_transports) {
        if(transport->getTransportType() == tr->getTransportType()) {
            tr->updateStunTimers();
        }
    }
}

void AmRtpStream::dtlsSessionActivated(AmMediaTransport* transport, uint16_t srtp_profile, const vector<uint8_t>& local_key, const vector<uint8_t>& remote_key)
{
    string l_key(local_key.size(), 0), r_key(remote_key.size(), 0);
    memcpy((void*)l_key.c_str(), local_key.data(), local_key.size());
    memcpy((void*)r_key.c_str(), remote_key.data(), remote_key.size());
    for(auto tr : ip4_transports) {
        if(transport->getTransportType() == tr->getTransportType())
            tr->initSrtpConnection(srtp_profile, l_key, r_key);
    }
    for(auto tr : ip6_transports) {
        if(transport->getTransportType() == tr->getTransportType())
            tr->initSrtpConnection(srtp_profile, l_key, r_key);
    }
}

#ifdef WITH_ZRTP
extern "C" {
#include <bzrtp/bzrtp.h>
}

void AmRtpStream::zrtpSessionActivated(const bzrtpSrtpSecrets_t* srtpSecrets)
{
    string l_key(srtpSecrets->selfSrtpKeyLength + srtpSecrets->selfSrtpSaltLength, 0),
           r_key(srtpSecrets->peerSrtpKeyLength + srtpSecrets->peerSrtpSaltLength, 0);
    memcpy((void*)l_key.c_str(), srtpSecrets->selfSrtpKey, srtpSecrets->selfSrtpKeyLength);
    memcpy((void*)(l_key.c_str() + srtpSecrets->selfSrtpKeyLength), srtpSecrets->selfSrtpSalt, srtpSecrets->selfSrtpSaltLength);
    memcpy((void*)r_key.c_str(), srtpSecrets->peerSrtpKey, srtpSecrets->peerSrtpKeyLength);
    memcpy((void*)(r_key.c_str() + srtpSecrets->peerSrtpKeyLength), srtpSecrets->peerSrtpSalt, srtpSecrets->peerSrtpSaltLength);

    uint16_t srtp_profile;
    if (srtpSecrets->authTagAlgo == ZRTP_AUTHTAG_HS32){
			if (srtpSecrets->cipherAlgo == ZRTP_CIPHER_AES3){
                srtp_profile = CP_AES256_CM_SHA1_32;
//             } else if(srtpSecrets->cipherAlgo == ZRTP_CIPHER_AES2){
//                 srtp_profile = CP_AES192_CM_SHA1_32;
            } else {
                srtp_profile = CP_AES128_CM_SHA1_32;
            }
    } else if (srtpSecrets->authTagAlgo == ZRTP_AUTHTAG_HS80){
			if (srtpSecrets->cipherAlgo == ZRTP_CIPHER_AES3){
                srtp_profile = CP_AES256_CM_SHA1_80;
//             } else if(srtpSecrets->cipherAlgo == ZRTP_CIPHER_AES2){
//                 srtp_profile = CP_AES192_CM_SHA1_80;
            } else {
                srtp_profile = CP_AES128_CM_SHA1_80;
            }
    } else {
        CLASS_ERROR("encryption methods with keys derived using ZRTP are not supported");
        return;
    }

    for(auto tr : ip4_transports) {
            tr->initSrtpConnection(srtp_profile, l_key, r_key);
    }
    for(auto tr : ip6_transports) {
            tr->initSrtpConnection(srtp_profile, l_key, r_key);
    }
}

int AmRtpStream::send_zrtp(unsigned char* buffer, unsigned int size)
{
    if ((mute) || (hold))
        return 0;

    AmRtpPacket rp;
    rp.compile_raw(buffer, size);
    sockaddr_storage raddr;
    cur_rtp_trans->getRAddr(false, &raddr);
    if(cur_rtp_trans && cur_rtp_trans->send(&raddr, buffer, size, AmStreamConnection::ZRTP_CONN) < 0) {
        CLASS_ERROR("while sending ZRTP packet.\n");
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

        add_if_no_exist(incoming_payloads,rp->payload);
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
        CLASS_ERROR("received too big RTP packet\n");
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
        if (force_receive_dtmf && isLocalTelephoneEventPayload(p->payload))
            recvDtmfPacket(p);

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
                CLASS_DBG("switching to relay-mode\t(ts=%u;stream=%p)\n",p->timestamp,this);
                active = false;
            }

            add_if_no_exist(incoming_relayed_payloads,p->payload);

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
    /*CLASS_DBG("DTMF: event=%i; e=%i; r=%i; volume=%i; duration=%i; ts=%u session = [%p]\n",
                dpl->event,dpl->e,dpl->r,dpl->volume,ntohs(dpl->duration),p->timestamp, session);*/
    if(session)
        session->postDtmfEvent(new AmRtpDtmfEvent(dpl, getLocalTelephoneEventRate(), p->timestamp));
}

int AmRtpStream::nextPacket(AmRtpPacket*& p)
{
    //if (!receiving && !getPassiveMode())
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
       (diff.tv_sec > 0) &&
       (static_cast<unsigned int>(diff.tv_sec) > dead_rtp_time))
    {
        CLASS_DBG("RTP Timeout detected. Last received packet is too old "
            "(diff.tv_sec = %i, limit = %i, "
            "local_ssrc: 0x%x, local_tag: %s)\n",
            static_cast<unsigned int>(diff.tv_sec),dead_rtp_time,
            l_ssrc,session ? session->getLocalTag().c_str() : "no session");
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
    if ((mute) || (hold))
        return 0;

    AmRtpPacket rp;
    rp.compile_raw(buffer, size);
    if(cur_udptl_trans && cur_udptl_trans->send(&rp, AmStreamConnection::UDPTL_CONN) < 0) {
        CLASS_ERROR("while sending RTP packet.\n");
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
        CLASS_ERROR("while sending RTP packet.\n");
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
    if ((mute) || (hold))
        return 0;

    if(process_dtmf_queue(user_ts))
        return size;

    if(!size)
        return -1;

    PayloadMappingTable::const_iterator it = pl_map.find(payload);
    if ((it == pl_map.end()) || (it->second.remote_pt < 0)) {
        if(!not_supported_tx_payload_reported) {
            CLASS_DBG("attempt to send packet with unsupported remote payload type %d\n", payload);
            not_supported_tx_payload_reported = true;
        }
        return 0;
    } else {
        not_supported_tx_payload_reported = false;
    }

    return compile_and_send(it->second.remote_pt, false, user_ts, buffer, size);
}

void AmRtpStream::relay(AmRtpPacket* p)
{
    // not yet initialized
    // or muted/on-hold
     if (mute || hold)
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

         /*if(process_dtmf_queue && remote_telephone_event_pt.get()) {
             hdr->ssrc = htonl(l_ssrc);
             if(dtmf_sender.sendPacket(p->timestamp,remote_telephone_event_pt->payload_type,this))
                 return;
         }*/

         if (!relay_transparent_seqno)
             hdr->seq = htons(sequence++);
         if (!relay_transparent_ssrc)
             hdr->ssrc = htonl(l_ssrc);

         hdr->pt = relay_map.get(hdr->pt);

         //if(relay_timestamp_aligning) {
         p->timestamp = get_adjusted_ts(p->timestamp);
         hdr->ts = htonl(p->timestamp);
         //}

     } //if(!relay_raw)

     if(cur_rtp_trans->send(p, relay_raw ? AmStreamConnection::RAW_CONN : AmStreamConnection::RTP_CONN) < 0) {
         CLASS_ERROR("while sending RTP packet to '%s':%i\n",
                    cur_rtp_trans->getRHost(false).c_str(),cur_rtp_trans->getRPort(false));
     } else {
        sockaddr_storage addr;
        if(relay_raw) cur_rtp_trans->getRAddr(&addr);
        else if(!relay_raw) cur_rtp_trans->getRAddr(false, &addr);
        if(session) session->onAfterRTPRelay(p, &addr);
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
        if(rtp_stats.rx.pkt) {
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
        if(rtp_stats.rx.pkt) {
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

void AmRtpStream::setMultiplexing(bool multiplex)
{
    CLASS_DBG("set using ice protocol");
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
    for(auto transport : ip4_transports) {
        transport->setPassiveMode(p);
    }
    for(auto transport : ip6_transports) {
        transport->setPassiveMode(p);
    }
}

void AmRtpStream::setReceiving(bool r)
{
    CLASS_DBG("set receiving=%s\n",r?"true":"false");
    receiving = r;
}

void AmRtpStream::pause()
{
    CLASS_DBG("pausing (receiving=false)\n");
    receiving = false;
}

void AmRtpStream::resume()
{
    CLASS_DBG("resuming (receiving=true, clearing biffers/TS/TO)\n");

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
    hold = on_hold;
}

bool AmRtpStream::getOnHold()
{
    return hold;
}

void AmRtpStream::setRelayStream(AmRtpStream* stream)
{
    relay_stream = stream;
    CLASS_DBG("set relay stream [%p]\n", stream);
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
    CLASS_DBG("enabled RTP relay\n");
    relay_enabled = true;
}

void AmRtpStream::disableRtpRelay()
{
    CLASS_DBG("disabled RTP relay\n");
    relay_enabled = false;
}

void AmRtpStream::setRawRelay(bool enable)
{
    CLASS_DBG("%sabled RAW relay\n", enable ? "en" : "dis");
    relay_raw = enable;
    if(cur_rtp_trans) {
        cur_rtp_trans->initRawConnection();
    }
}

bool AmRtpStream::isRawRelay()
{
    return relay_raw;
}

void AmRtpStream::setRtpRelayTransparentSeqno(bool transparent)
{
    CLASS_DBG("%sabled RTP relay transparent seqno\n",
        transparent ? "en":"dis");
    relay_transparent_seqno = transparent;
}

void AmRtpStream::setRtpRelayTransparentSSRC(bool transparent)
{
    CLASS_DBG("%sabled RTP relay transparent SSRC\n",
        transparent ? "en":"dis");
     relay_transparent_ssrc = transparent;
}

void AmRtpStream::setRtpRelayFilterRtpDtmf(bool filter)
{
    CLASS_DBG("%sabled RTP relay filtering of RTP DTMF (2833 / 3744)\n",
        filter ? "en":"dis");
    relay_filter_dtmf = filter;
}

void AmRtpStream::setRtpRelayTimestampAligning(bool enable_aligning)
{
    CLASS_DBG("%sabled RTP relay timestamp aligning\n",
        enable_aligning ? "en":"dis");
    relay_timestamp_aligning = enable_aligning;
    if(relay_timestamp_aligning) {
        CLASS_DBG("relay_timestamp_aligning is deprecated because of using timestamp from media processor as reference for relay");
    }
}

void AmRtpStream::setRtpForceRelayDtmf(bool relay)
{
    CLASS_DBG("%sabled force relay of RTP DTMF (2833 / 3744)\n",
        relay ? "en":"dis");
    force_relay_dtmf = relay;
}

void AmRtpStream::setRtpForceRelayCN(bool relay)
{
    CLASS_DBG("%sabled force relay CN payload\n",
        relay ? "en":"dis");
    force_relay_cn = relay;
}

void AmRtpStream::setSymmetricRtpEndless(bool endless)
{
    CLASS_DBG("%sabled endless symmetric RTP switching\n",
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
    CLASS_DBG("%sabled RTP Ping\n", enable ? "en":"dis");
    rtp_ping = enable;
}

void AmRtpStream::setRtpTimeout(unsigned int timeout)
{
    dead_rtp_time = timeout;
    CLASS_DBG("set RTP dead time to %i\n", dead_rtp_time);
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
    for(auto& transport : ip4_transports) {
        transport->stopReceiving();
    }
    for(auto& transport : ip6_transports) {
        transport->stopReceiving();
    }
}

void AmRtpStream::resumeReceiving()
{
    for(auto& transport : ip4_transports) {
        transport->resumeReceiving();
    }
    for(auto& transport : ip6_transports) {
        transport->resumeReceiving();
    }
}

void AmRtpStream::setLogger(msg_logger* _logger)
{
    for(auto trans : ip4_transports) {
        trans->setLogger(_logger);
    }
    for(auto trans : ip6_transports) {
        trans->setLogger(_logger);
    }
}

void AmRtpStream::setSensor(msg_sensor *_sensor)
{
    CLASS_DBG("AmRtpStream: change sensor to %p",_sensor);
    for(auto trans : ip4_transports) {
        trans->setSensor(_sensor);
    }
    for(auto trans : ip6_transports) {
        trans->setSensor(_sensor);
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                   help functions

void AmRtpStream::replaceAudioMediaParameters(SdpMedia &m, unsigned int idx, const string& relay_address)
{
    CLASS_DBG("replaceAudioMediaParameters() relay_address: %s",
              relay_address.c_str());

    setLocalIP(relay_address);

    m.port = static_cast<unsigned int>(getLocalPort());
    //replace rtcp attribute
    for(auto &a : m.attributes) {
        try {
            if (a.attribute == "rtcp") {
                RtcpAddress addr(a.value);
                addr.setPort(getLocalRtcpPort());
                if (addr.hasAddress()) addr.setAddress(relay_address);
                a.value = addr.print();
            }
        } catch (const std::exception &e) {
            DBG("can't replace RTCP address: %s\n", e.what());
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
        cur_rtp_trans->getSdpOffer(m);
        break;
    case AmOfferAnswer::OA_OfferRecved:
    case AmOfferAnswer::OA_Completed: {
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

void AmRtpStream::getMediaStats(struct MediaStats &s)
{
    auto &rx  = s.rx;
    auto &tx = s.tx;

    s.dropped = dropped_packets_count;
    s.rtt = rtp_stats.rtt;
    memcpy(&s.time_start, &start_time, sizeof(struct timeval));
    gettimeofday(&s.time_end, nullptr);

    //RX rtp_common
    rx.ssrc = r_ssrc;
    if(cur_rtp_trans) {
        cur_rtp_trans->getRAddr(&rx.addr);
    } else {
         memset(&rx.addr, 0, sizeof(struct sockaddr_storage));
    }
    rx.pkt = rtp_stats.rx.pkt;
    rx.bytes = rtp_stats.rx.bytes;
    rx.total_lost = rtp_stats.total_lost;
    payloads_id2str(incoming_payloads,rx.payloads_transcoded);
    payloads_id2str(incoming_relayed_payloads,rx.payloads_relayed);

    //RX specific
    rx.decode_errors = decode_errors;
    rx.rtp_parse_errors = rtp_parse_errors;
    rx.srtp_decript_errors = srtp_unprotect_errors;
    rx.out_of_buffer_errors = out_of_buffer_errors;
    rx.delta = rtp_stats.rx_delta;
    rx.jitter = rtp_stats.jitter;
    rx.rtcp_jitter = rtp_stats.rtcp_jitter;

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
    session->getMediaAcl(acl);
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

    CLASS_DBG("\tmute: %s, hold: %s, receiving: %s",
        BOOL_STR(mute), BOOL_STR(hold), BOOL_STR(receiving));
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
    ret["hold"] = hold;
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

    rtp_stats.init_seq(p.sequence);
    rtp_stats.max_seq--;
    rtp_stats.probation = MIN_SEQUENTIAL;
}

void AmRtpStream::update_receiver_stats(const AmRtpPacket &p)
{
    AmLock l(rtp_stats);

    if((!r_ssrc_i) || (p.ssrc!=r_ssrc))
        init_receiver_info(p);

    rtp_stats.rx.pkt++;
    rtp_stats.rx.bytes += p.getDataSize();

    if(!rtp_stats.update_seq(p.sequence)) {
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
        rtp_stats.rx.rtcp_jitter += d - ((rtp_stats.rx.rtcp_jitter + 8) >> 4);
    }
    rtp_stats.transit = transit;

    if(timerisset(&rtp_stats.rx_recv_time)) {
        timeval diff;
        timersub(&p.recv_time, &rtp_stats.rx_recv_time, &diff);
        rtp_stats.rx_delta.update((diff.tv_sec * 1000000) + diff.tv_usec);
        if(rtp_stats.rx_delta.n && rtp_stats.rx_delta.n % 250) {
            //update jitter every 250 packets (5 seconds)
            rtp_stats.jitter.update(rtp_stats.rx_delta.sd());
        }
    }
    rtp_stats.rx_recv_time = p.recv_time;
}

void AmRtpStream::fill_receiver_report(RtcpReceiverReportHeader &r, struct timeval &now)
{
    struct timeval delay;

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

    uint32_t jitter = rtp_stats.rx.rtcp_jitter >> 4;
    r.jitter = htonl(jitter);

    //update stats
    rtp_stats.rtcp_jitter.update(jitter);
}

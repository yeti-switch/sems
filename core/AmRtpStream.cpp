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
#include "media/AmMediaEndpoint.h"
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

#define ts_unsigned_diff(a, b) ((a) >= (b) ? (a) - (b) : (b) - (a))

// max_frame_size * 20
#define RTP_TIMESTAMP_ALINGING_MAX_TS_DIFF (200 * 20)

#define RTCP_REPORT_SEND_INTERVAL_SECONDS 3
#define ICE_PWD_SIZE                      22
#define ICE_UFRAG_SIZE                    4

#define BIND_ATTEMPTS_COUNT 10

#define MAX_TRANSPORTS_COUNT 8

static inline void add_if_no_exist(std::vector<int> &v, int payload)
{
    if (std::find(v.begin(), v.end(), payload) == v.end())
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
    unsigned long long *ull = (unsigned long long *)bits;
    ull[0]                  = ~ull[0];
    ull[1]                  = ~ull[1];
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

AmRtpStream::AmRtpStream(AmSession *_s, int _if, int media_index)
    : endpoint(nullptr)
    , pending_endpoint(nullptr)
    , tx_user_ts(0)
    , last_send_rtcp_report_ts(0)
    , outgoing_bytes(0)
    , last_not_supported_rx_payload(-1)
    , last_not_supported_tx_payload(-1)
    , wrong_payload_errors(0)
    , dead_rtp_time(AmConfig.dead_rtp_time)
    , relay_ts_shift(0)
    , sdp_media_index(media_index)
    , disabled(false)
    , transport(TP_NONE)
    , last_recv_payload(-1)
    , last_recv_relayed(false)
    , last_recv_ts(0)
    , recent_cn_observed(false)
    , l_if(_if)
    , r_ssrc_i(false)
    , bundle_enabled(false)
    , bundle_mid_ext_id(0)
    , monitor_rtp_timeout(true)
    , mute(false)
    , sending(true)
    , receiving(true)
    , relay_enabled(false)
    , relay_raw(false)
    , relay_stream(NULL)
    , relay_transparent_seqno(false)
    , relay_transparent_ssrc(false)
    , relay_filter_dtmf(false)
    , force_relay_dtmf(true)
    , relay_timestamp_aligning(false)
    , rtp_ping(false)
    , force_buffering(false)
    , session(_s)
    , active(false)
    , force_receive_dtmf(false)
{
    DBG("AmRtpStream[%p](%p)", this, session);

    l_ssrc   = get_random();
    sequence = get_random();
    clearRTPTimeout();

    // by default the system codecs
    payload_provider = AmPlugIn::instance();

    bzero(local_telephone_event_payloads, sizeof(local_telephone_event_payloads));
}

AmRtpStream::~AmRtpStream()
{
    DBG("~AmRtpStream[%p]() session = %p", this, session);
    if (session)
        session->onRTPStreamDestroy(this);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                   functions for job with sdp message(answer, offer)

void AmRtpStream::getSdp(SdpMedia &m)
{
    // media-level fields only; the transport-level part is filled by endpoint
    m.send = sending;
    m.recv = receiving;
    m.dir  = SdpMedia::DirBoth;
    m.ssrc = l_ssrc;
}

void AmRtpStream::getSdpOffer(SdpMedia &offer)
{
    CLASS_DBG("AmRtpStream::getSdpOffer(media_index = %d)", sdp_media_index);

    if (disabled) { // RFC 3264: disabled m= line - port 0, but keep the media type/proto
        offer.type      = getMediaType();
        offer.transport = transport;
        offer.port      = 0;
        offer.send      = false;
        offer.recv      = false;
        return;
    }

    AmMediaEndpoint *ep = sdpEndpoint();
    if (session) {
        auto session_trsp = session->getMediaTransport();
        if (session_trsp != TP_NONE) {
            setTransport(session_trsp); // caches transport on the stream + sets the endpoint
        }

        if (!ep->isIceStream())
            ep->setIceStream(session->isUseIceMediaStream());
    }

    getSdp(offer);
    offer.payloads.clear();

    if (ep->getTransport() != TP_UDPTL && ep->getTransport() != TP_UDPTLSUDPTL)
        payload_provider->getPayloads(offer.payloads);
    ep->fillSdpOffer(offer);

    // BUNDLE (RFC 9143): mark this m= section bundle-capable
    // BUNDLE applies to RTP media only - never to T.38/UDPTL fax (MT_IMAGE)
    bundle_enabled =
        getMediaType() == MT_AUDIO && session && session->isBundleMediaStream() && AmConfig.enable_media_bundling;
    if (bundle_enabled) {
        if (offer.mid.empty())
            offer.mid = int2str(sdp_media_index);
        offer.use_bundle = true;
        // MID RTP header extension - needed to demux bundled RTP (RFC 8843)
        bool has_mid_ext = false;
        for (const auto &e : offer.extmaps)
            if (e.uri == MID_RTP_HDREXT_URI) {
                has_mid_ext = true;
                break;
            }
        if (!has_mid_ext)
            offer.extmaps.push_back(SdpExtMap(MID_RTP_HDREXT_DEFAULT_ID, MID_RTP_HDREXT_URI));
    }
}

void AmRtpStream::getSdpAnswer(const SdpMedia &offer, SdpMedia &answer)
{
    CLASS_DBG("AmRtpStream::getSdpAnswer(media_index = %d)", sdp_media_index);

    if (disabled) { // RFC 3264: disabled m= line - port 0, but keep the media type/proto
        answer.type      = getMediaType();
        answer.transport = transport;
        answer.port      = 0;
        answer.send      = false;
        answer.recv      = false;
        return;
    }

    if (offer.is_use_ice() && !AmConfig.enable_ice) {
        throw AmSession::Exception(488, "transport is not supported");
    }

    setTransport(offer.transport);
    AmMediaEndpoint *ep = sdpEndpoint();
    ep->setIceStream(offer.is_use_ice() && (session ? session->isUseIceMediaStream() : false));

    getSdp(answer);
    offer.calcAnswer(payload_provider, answer);

    ep->fillSdpAnswer(offer, answer);

    // BUNDLE (RFC 9143): echo the offered mid (RFC 5888 9.1)
    // BUNDLE applies to RTP media only - never to T.38/UDPTL fax (MT_IMAGE)
    bundle_enabled =
        getMediaType() == MT_AUDIO && session && session->isBundleMediaStream() && AmConfig.enable_media_bundling;
    if (bundle_enabled && offer.use_bundle && !offer.mid.empty()) {
        answer.mid        = offer.mid;
        answer.use_bundle = true;
        // echo the offered MID extension keeping its id (RFC 8285 6)
        for (const auto &e : offer.extmaps)
            if (e.uri == MID_RTP_HDREXT_URI) {
                answer.extmaps.push_back(SdpExtMap(e.id, e.uri));
                break;
            }
    }
}

AmRtpStream::InitResult AmRtpStream::init(const AmSdp &local, const AmSdp &remote, bool sdp_offer_owner,
                                          bool force_passive_mode)
{
    init_error.clear();
    if ((sdp_media_index < 0) || ((unsigned)sdp_media_index >= local.media.size()) ||
        ((unsigned)sdp_media_index >= remote.media.size()))
    {
        CLASS_ERROR("Media index %i is invalid, either within local or remote SDP (or both)", sdp_media_index);
        init_error = "Media index is invalid";
        return InitResult::TransportError;
    }


    const SdpMedia &local_media  = local.media[sdp_media_index];
    const SdpMedia &remote_media = remote.media[sdp_media_index];

    CLASS_DBG("AmRtpStream[%p]::init() sdp_media_index = %d, sdp_offer_owner = %d", this, sdp_media_index,
              sdp_offer_owner);

    // BUNDLE (RFC 9143): cache the mid and MID RTP header extension id to stamp outgoing RTP
    bundle_mid.clear();
    bundle_mid_ext_id = 0;
    if (bundle_enabled && local_media.use_bundle) {
        bundle_mid = local_media.mid;
        for (const auto &e : local_media.extmaps)
            if (e.uri == MID_RTP_HDREXT_URI) {
                bundle_mid_ext_id = e.id;
                break;
            }
    }

    if (local_media.type == MT_AUDIO) {
        payloads.clear();
        pl_map.clear();
        payloads.resize(local_media.payloads.size());

        int                                i      = 0;
        vector<SdpPayload>::const_iterator sdp_it = local_media.payloads.begin();
        vector<Payload>::iterator          p_it   = payloads.begin();

        // first pass on local SDP - fill pl_map with intersection of codecs
        while (sdp_it != local_media.payloads.end()) {
            int int_pt;

            bool isAllowTransport = (local_media.transport == TP_RTPAVP || local_media.transport == TP_UDPTLSRTPSAVP ||
                                     local_media.transport == TP_RTPSAVP);
            if (isAllowTransport && sdp_it->payload_type < 20)
                int_pt = sdp_it->payload_type;
            else
                int_pt =
                    payload_provider->getDynPayload(sdp_it->encoding_name, sdp_it->clock_rate, sdp_it->encoding_param);

            amci_payload_t *a_pl = NULL;
            if (int_pt >= 0)
                a_pl = payload_provider->payload(int_pt);

            if (a_pl == NULL) {
                if (relay_payloads.get(sdp_it->payload_type)) {
                    // this payload should be relayed, ignore
                    ++sdp_it;
                    continue;
                } else {
                    CLASS_DBG("No internal payload corresponding to type %s/%i (ignoring)",
                              sdp_it->encoding_name.c_str(), sdp_it->clock_rate);
                    // ignore this payload
                    ++sdp_it;
                    continue;
                }
            }

            p_it->pt                    = sdp_it->payload_type;
            p_it->name                  = sdp_it->encoding_name;
            p_it->codec_id              = a_pl->codec_id;
            p_it->clock_rate            = a_pl->sample_rate;
            p_it->advertised_clock_rate = sdp_it->clock_rate;

            pl_map[sdp_it->payload_type].index     = i;
            pl_map[sdp_it->payload_type].remote_pt = -1;

            ++p_it;
            ++sdp_it;
            ++i;
        } // while(sdp_it != local_media.payloads.end())

        // remove payloads which were not initialised (because of unknown payloads
        // which are to be relayed)
        if (p_it != payloads.end())
            payloads.erase(p_it, payloads.end());

        // second pass on remote SDP - initialize payload IDs used by remote (remote_pt)
        sdp_it = remote_media.payloads.begin();
        while (sdp_it != remote_media.payloads.end()) {

            // TODO: match not only on encoding name
            //       but also on parameters, if necessary
            //       Some codecs define multiple payloads
            //       with different encoding parameters
            PayloadMappingTable::iterator pmt_it = pl_map.end();
            bool isAllowTransport = (local_media.transport == TP_RTPAVP || local_media.transport == TP_UDPTLSRTPSAVP ||
                                     local_media.transport == TP_RTPSAVP);
            if (sdp_it->encoding_name.empty() || (isAllowTransport && sdp_it->payload_type < 20)) {
                // must be a static payload
                pmt_it = pl_map.find(sdp_it->payload_type);
            } else {
                for (p_it = payloads.begin(); p_it != payloads.end(); ++p_it) {
                    if (!strcasecmp(p_it->name.c_str(), sdp_it->encoding_name.c_str()) &&
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
            if (pmt_it != pl_map.end() && (pmt_it->second.remote_pt < 0)) {
                pmt_it->second.remote_pt = sdp_it->payload_type;
            }
            ++sdp_it;
        } // while(sdp_it != remote_media.payloads.end())

        // set remote address - media c-line having precedence over session c-line
        if (remote.conn.address.empty() && remote_media.conn.address.empty()) {
            CLASS_WARN("no c= line given globally or in m= section in remote SDP");
            init_error = "no remote address";
            return InitResult::TransportError;
        }

        if (local_media.payloads.empty()) {
            CLASS_DBG("local_media.payloads.empty()");
            init_error = "no payloads";
            return InitResult::CodecError;
        }

        // find telephone-event intersections
        local_telephone_event_pt.reset(nullptr);
        remote_telephone_event_pt.reset(nullptr);
        for (auto const &remote_payload : remote_media.payloads) {
            if (remote_payload.encoding_name == "telephone-event") {
                for (auto const &local_payload : local_media.payloads) {
                    if (local_payload.encoding_name == "telephone-event" &&
                        remote_payload.clock_rate == local_payload.clock_rate)
                    {
                        local_telephone_event_pt.reset(new SdpPayload(local_payload));
                        remote_telephone_event_pt.reset(new SdpPayload(remote_payload));
                        break;
                    }
                }
                if (local_telephone_event_pt.get()) // use first matched pair
                    break;
            }
        }

        // fill local telephone-event payloads bitset
        bzero(local_telephone_event_payloads, sizeof(local_telephone_event_payloads));
        for (auto const &p : local_media.payloads) {
            if (p.encoding_name == "telephone-event") {
                set_bit(p.payload_type % BITS_PER_LONG,
                        &local_telephone_event_payloads[p.payload_type >> _BITOPS_LONG_SHIFT]);
            }
        }

        if (remote_telephone_event_pt.get()) {
            CLASS_DBG("remote party supports telephone events (pt=%i)", remote_telephone_event_pt->payload_type);
        } else {
            CLASS_DBG("remote party doesn't support telephone events");
        }

        // find comfort-noise (RFC 3389) intersection
        remote_comfort_noise_pt.reset(nullptr);
        for (auto const &remote_payload : remote_media.payloads) {
            if (strcasecmp(remote_payload.encoding_name.c_str(), "CN"))
                continue;
            for (auto const &local_payload : local_media.payloads) {
                if (!strcasecmp(local_payload.encoding_name.c_str(), "CN") &&
                    remote_payload.clock_rate == local_payload.clock_rate)
                {
                    remote_comfort_noise_pt.reset(new SdpPayload(remote_payload));
                    break;
                }
            }
            if (remote_comfort_noise_pt.get())
                break;
        }

        payload = getDefaultPT();
        if (payload < 0) {
            CLASS_DBG("could not set a default payload");
            init_error = "could not set a default payload";
            return InitResult::CodecError;
        }
        CLASS_DBG("default payload selected = %i", payload);
        last_payload = payload;
    }

    CLASS_DBG("use transport = %d", local_media.transport);
    CLASS_DBG("local direction = %u, remote direction = %u", local_media.dir, remote_media.dir);
    CLASS_DBG("local setup = %u, remote setup = %u", local_media.setup, remote_media.setup);
#ifdef WITH_ZRTP
    CLASS_DBG("local media attribute: use_ice - %s, dtls - %s, srtp - %s, zrtp - %s",
#else  /*WITH_ZRTP*/
    CLASS_DBG("local media attribute: use_ice - %s, dtls - %s, srtp - %s",
#endif /*WITH_ZRTP*/
              local_media.is_use_ice() ? "true" : "false",
              (local_media.is_dtls_srtp() || local_media.is_dtls_udptl()) ? "true" : "false",
              (local_media.is_simple_srtp() || local_media.is_dtls_srtp()) ? "true" : "false"
#ifdef WITH_ZRTP
              ,
              local_media.zrtp_hash.is_use ? "true" : "false");
#else  /*WITH_ZRTP*/
    );
#endif /*WITH_ZRTP*/
#ifdef WITH_ZRTP
    CLASS_DBG("remote media attribute: use_ice - %s, dtls - %s, srtp - %s, zrtp - %s",
#else  /*WITH_ZRTP*/
    CLASS_DBG("remote media attribute: use_ice - %s, dtls - %s, srtp - %s",
#endif /*WITH_ZRTP*/
              remote_media.is_use_ice() ? "true" : "false",
              (remote_media.is_dtls_srtp() || remote_media.is_dtls_udptl()) ? "true" : "false",
              (remote_media.is_simple_srtp() || remote_media.is_dtls_srtp()) ? "true" : "false"
#ifdef WITH_ZRTP
              ,
              local_media.zrtp_hash.is_use ? "true" : "false");
#else  /*WITH_ZRTP*/
    );
#endif /*WITH_ZRTP*/

    if (!remote_media.cname.empty())
        r_ssrc = remote_media.ssrc;
    if (!local_media.cname.empty())
        l_ssrc = local_media.ssrc;

    // transport-level setup (DTLS/SRTP/ICE/ZRTP/UDPTL/RTP state) lives in the endpoint
    if (getEndpoint()->init(local, remote, sdp_media_index, sdp_offer_owner, force_passive_mode, init_error) < 0)
        return InitResult::TransportError;

    bool connection_is_muted = getEndpoint()->isConnectionMuted();
    bool relay_is_muted      = getEndpoint()->isRelayMuted();

    sending = local_media.send;

    CLASS_DBG("local_recv:%d, local_send:%d, remote_recv:%d, remote_send:%d "
              "sending:%d remote_media.port:%u relay_is_muted:%d, conn_mute: %d",
              local_media.recv, local_media.send, remote_media.recv, remote_media.send, sending, remote_media.port,
              relay_is_muted, connection_is_muted);

    if (local_media.recv && remote_media.send) {
        resume();
    } else {
        pause();
    }

    sending = local_media.send;
    mute    = (remote_media.port < 1024) || // fake ports see https://datatracker.ietf.org/doc/html/rfc2327 p.18
           relay_is_muted || connection_is_muted;

    CLASS_DBG("mute = %d", mute);

    if (!timerisset(&rtp_stats.start))
        gettimeofday(&rtp_stats.start, nullptr);

    rtcp_reports.init(l_ssrc, local_media.cname);

    last_not_supported_rx_payload = -1;
    last_not_supported_tx_payload = -1;

    active = false; // mark as nothing received yet

    return InitResult::Ok;
}

// returns
// @param ts              [out] timestamp of the received packet,
//                              in audio buffer relative time
// @param audio_buffer_ts [in]  current ts at the audio_buffer

int AmRtpStream::receive(unsigned char *buffer, unsigned int size)
{
    AmRtpPacket *rp  = NULL;
    int          err = nextPacket(rp);

    if (err <= 0)
        return err;

    if (!rp)
        return 0;

    last_recv_relayed = rp->relayed;

    if (!last_recv_relayed) {
        /* do we have a new talk spurt? */
        begin_talk         = recent_cn_observed || rp->marker;
        recent_cn_observed = false;
        last_payload       = last_recv_payload;

        add_if_no_exist(incoming_payloads[r_ssrc], rp->payload);
    }

    if (!rp->getDataSize()) {
        rp->release();
        return RTP_EMPTY;
    }

    if (isLocalTelephoneEventPayload(rp->payload)) {
        if (!last_recv_relayed)
            recvDtmfPacket(rp);
        rp->release();
        return RTP_DTMF;
    }

    assert(rp->getData());
    if (rp->getDataSize() > size) {
        CLASS_ERROR("received too big RTP packet");
        rp->release();
        return RTP_BUFFER_SIZE;
    }

    memcpy(buffer, rp->getData(), rp->getDataSize());

    last_recv_ts      = rp->timestamp;
    last_recv_payload = rp->payload;

    int res = rp->getDataSize();
    rp->release();
    return res;
}

void AmRtpStream::bufferPacket(AmRtpPacket *p)
{
    clearRTPTimeout(&p->recv_time);
    update_receiver_stats(*p);

    if (!receiving) {
        if (force_receive_dtmf && isLocalTelephoneEventPayload(p->payload))
            recvDtmfPacket(p);
        p->release();
        return;
    }

    if (isPayloadCN(p->payload))
        recent_cn_observed = true;

    if (relay_enabled) {
        // CN is interleaved with audio; bypass the last_payload consistency check
        bool can_relay_cn =
            force_relay_cn && relay_stream != nullptr && relay_payloads.get(p->payload) && isPayloadCN(p->payload);

        if (relay_raw ||
            /*(p->payload == getLocalTelephoneEventPT()
             && (force_relay_dtmf || !active)) ||*/
            // can relay
            (relay_payloads.get(p->payload) && nullptr != relay_stream &&
             // check if actual remote payload mapping to local payload are equal
             p->payload == relay_map.get(static_cast<unsigned char>(relay_stream->getLastPayload()))) ||
            can_relay_cn)
        {
            if (active) {
                CLASS_DBG("switching to relay-mode\t(ts=%u;stream=%p)", p->timestamp, this);
                active = false;
            }

            add_if_no_exist(incoming_relayed_payloads[r_ssrc], p->payload);

            if (NULL != relay_stream) // packet is not dtmf or relay dtmf is not filtered
            {
                relay_stream->relay(p);
                if (force_buffering && p->relayed) {
                    receive_mut.lock();
                    if (!receive_buf.insert(ReceiveBuffer::value_type(p->timestamp, p)).second) {
                        p->release();
                    }
                    receive_mut.unlock();
                    return;
                }
            }
            p->release();
            return;
        }
    } // if(relay_enabled)

    // throw away ZRTP packets
    if (p->version != RTP_VERSION) {
        p->release();
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

    if (isLocalTelephoneEventPayload(p->payload)) {
        rtp_ev_qu.push(p);
    } else {
        if (!receive_buf.insert(ReceiveBuffer::value_type(p->timestamp, p)).second) {
            // insert failed
            p->release();
        }
    }
    receive_mut.unlock();
}

void AmRtpStream::recvDtmfPacket(AmRtpPacket *p)
{
    if (p->getDataSize() != sizeof(dtmf_payload_t))
        return;
    auto dpl = reinterpret_cast<dtmf_payload_t *>(p->getData());
    /*CLASS_DBG("DTMF: event=%i; e=%i; r=%i; volume=%i; duration=%i; ts=%u session = [%p]",
                dpl->event,dpl->e,dpl->r,dpl->volume,ntohs(dpl->duration),p->timestamp, session);*/
    if (session)
        session->postDtmfEvent(new AmRtpDtmfEvent(dpl, getLocalTelephoneEventRate(), p->timestamp));
}

int AmRtpStream::nextPacket(AmRtpPacket *&p)
{
    // if (!receiving)
    //  ignore 'passive' flag to avoid false RTP timeout for passive stream in sendonly mode
    if (!receiving)
        return RTP_EMPTY;

    struct timeval now;
    struct timeval diff;
    gettimeofday(&now, NULL);

    receive_mut.lock();
    timersub(&now, &last_recv_time, &diff);

    if (monitor_rtp_timeout && dead_rtp_time && sending && (diff.tv_sec > 0) &&
        (static_cast<unsigned int>(diff.tv_sec) > dead_rtp_time))
    {
        CLASS_DBG("RTP Timeout detected. Last received packet is too old "
                  "(diff.tv_sec = %i, limit = %i, "
                  "local_ssrc: 0x%x, local_tag: %s)\n",
                  static_cast<unsigned int>(diff.tv_sec), dead_rtp_time, l_ssrc,
                  session ? session->getLocalTag().data() : "null");
        receive_mut.unlock();
        return RTP_TIMEOUT;
    }

    if (!rtp_ev_qu.empty()) {
        // first return RTP telephone event payloads
        p = rtp_ev_qu.front();
        rtp_ev_qu.pop();
        receive_mut.unlock();
        return 1;
    }

    if (receive_buf.empty()) {
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
    if (!receive_buf.empty()) {
        p = receive_buf.begin()->second;
        receive_buf.erase(receive_buf.begin());
    }
    receive_mut.unlock();
    return p;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                   send functions
int AmRtpStream::send_udptl(unsigned int ts, unsigned char *buffer, unsigned int size)
{
    if ((mute) || (!sending))
        return 0;

    AmRtpPacket rp;
    rp.compile_raw(buffer, size);
    if (getEndpoint()->sendUdptl(&rp) < 0) {
        CLASS_ERROR("while sending RTP packet.");
        return -1;
    }

    return size;
}

int AmRtpStream::compile_and_send(const int payload, bool marker, unsigned int ts, unsigned char *buffer,
                                  unsigned int size)
{
    AmRtpPacket rp;
    rp.payload   = payload;
    rp.timestamp = ts;
    rp.marker    = marker;
    rp.sequence  = sequence++;
    rp.ssrc      = l_ssrc;
    // BUNDLE (RFC 9143): stamp the MID RTP header extension so the peer can demux (RFC 8843).
    // Covers audio, DTMF, comfort-noise and ping - they all reach here.
    if (bundle_mid_ext_id && !bundle_mid.empty())
        rp.addHeaderExtension(bundle_mid_ext_id, (const unsigned char *)bundle_mid.data(), bundle_mid.size());
    rp.compile((unsigned char *)buffer, size);

    if (getEndpoint()->sendRtp(&rp, AmStreamConnection::RTP_CONN) < 0) {
        CLASS_ERROR("while sending RTP packet.");
        return -1;
    }

    add_if_no_exist(outgoing_payloads, rp.payload);
    outgoing_bytes += rp.getDataSize();

    return size;
}

bool AmRtpStream::process_dtmf_queue(unsigned int ts)
{
    if (remote_telephone_event_pt.get() && dtmf_sender.sendPacket(ts, remote_telephone_event_pt->payload_type, this)) {
        return true;
    }
    return false;
}

void AmRtpStream::enableComfortNoise(unsigned int level, unsigned int interval_ms)
{
    unsigned int rate = remote_comfort_noise_pt.get() ? remote_comfort_noise_pt->clock_rate : 8000;
    cn_sender.enable(level, interval_ms * rate / 1000);
}

unsigned int AmRtpStream::get_adjusted_ts(unsigned int ts)
{
    auto adjusted_ts = static_cast<decltype(tx_user_ts)>(ts + relay_ts_shift);
    auto ts_diff     = tx_user_ts ? ts_unsigned_diff(adjusted_ts, tx_user_ts) : 0;

    /*CLASS_DBG("get_adjusted_ts(ts = %u) tx_user_ts = %llu",
              ts, tx_user_ts);*/

    if (ts_diff > RTP_TIMESTAMP_ALINGING_MAX_TS_DIFF) {
        CLASS_DBG("timestamp adjust condition reached: "
                  "ts: %u, adjusted_ts: %llu, tx_user_ts: %llu, "
                  "relay_ts_shift: %ld, ts_diff: %llu, "
                  "max_ts_diff: %u",
                  ts, adjusted_ts, tx_user_ts, relay_ts_shift, ts_diff, RTP_TIMESTAMP_ALINGING_MAX_TS_DIFF);

        auto old_ts_adjust = relay_ts_shift;

        relay_ts_shift = tx_user_ts - ts;

        CLASS_DBG("relay_ts_shift changed from %ld to %ld", old_ts_adjust, relay_ts_shift);

        adjusted_ts = static_cast<unsigned int>(ts + relay_ts_shift);
    }

    return adjusted_ts;
}

int AmRtpStream::send(unsigned int user_ts, unsigned char *buffer, unsigned int size)
{
    if ((mute) || (!sending))
        return 0;

    if (process_dtmf_queue(user_ts))
        return size;

    if (!size)
        return -1;

    if (payload == last_not_supported_tx_payload) {
        // attempt to send payload known as not supported. skip processing
        return 0;
    }

    auto it = pl_map.find(payload);
    if ((it == pl_map.end()) || (it->second.remote_pt < 0)) {
        CLASS_DBG("attempt to send packet with unsupported remote payload type %d", payload);
        last_not_supported_tx_payload = payload;
        return 0;
    }

    last_not_supported_tx_payload = -1;

    int ret = compile_and_send(it->second.remote_pt, false, user_ts, buffer, size);

    if (ret < 0 && session)
        session->postEvent(new AmRtpSendingErrorEvent());

    return ret;
}

void AmRtpStream::relay(AmRtpPacket *p)
{
    // not yet initialized
    // or muted/on-hold
    if (mute || (!sending))
        return;

    sockaddr_storage recv_addr;
    p->getAddr(&recv_addr);
    if (session && !session->onBeforeRTPRelay(p, &recv_addr))
        return;

    if (!relay_raw) {

        if (dtmf_sender.isSending())
            return;

        if (!tx_user_ts) {
            // no reference ts yet. skip sending
            return;
        }

        rtp_hdr_t *hdr = reinterpret_cast<rtp_hdr_t *>(p->getBuffer());

        if (!relay_transparent_seqno)
            hdr->seq = htons(sequence++);
        if (!relay_transparent_ssrc)
            hdr->ssrc = htonl(l_ssrc);

        hdr->pt = relay_map.get(hdr->pt);

        p->timestamp = get_adjusted_ts(p->timestamp);
        hdr->ts      = htonl(p->timestamp);
    } // if(!relay_raw)

    if (getEndpoint()->sendRtp(p, relay_raw ? AmStreamConnection::RAW_CONN : AmStreamConnection::RTP_CONN) < 0) {
        if (AmConfig.rtp_send_errors_log_level >= 0) {
            _LOG(AmConfig.rtp_send_errors_log_level, "while sending RTP packet to '%s':%i",
                 getEndpoint()->getRHost(RTP_TRANSPORT).c_str(), getEndpoint()->getRPort(RTP_TRANSPORT));
        }

        if (session)
            session->postEvent(new AmRtpSendingErrorEvent());

    } else {
        p->relayed = true;
        if (session) {
            sockaddr_storage addr;
            if (relay_raw) {
                getEndpoint()->getRAddr(&addr);
            } else {
                getEndpoint()->getRAddr(RTP_TRANSPORT, &addr);
            }
            session->onAfterRTPRelay(p, &addr);
        }
        add_if_no_exist(outgoing_relayed_payloads, p->payload);
        outgoing_bytes += p->getBufferSize();
    }
}

void AmRtpStream::processRtcpTimers(unsigned long long system_ts, unsigned int user_ts)
{
    unsigned long long scaled_ts = system_ts / WALLCLOCK_RATE;

    if (!last_send_rtcp_report_ts) {
        last_send_rtcp_report_ts = scaled_ts;
    } else {
        if ((scaled_ts - last_send_rtcp_report_ts) > RTCP_REPORT_SEND_INTERVAL_SECONDS) {
            last_send_rtcp_report_ts = scaled_ts;
            rtcp_send_report(user_ts);
        }
    }
}

void AmRtpStream::rtcp_send_report(unsigned int user_ts)
{
    void          *buf;
    unsigned int   len;
    struct timeval now;

    if (l_if < 0)
        return;

    gettimeofday(&now, nullptr);

    rtp_stats.lock();

    if (rtp_stats.tx.pkt) {
        if (rtp_stats.current_rx && rtp_stats.current_rx->pkt) {
            // SR with RR data
            fill_sender_report(rtcp_reports.sr.sr.sender, now, user_ts);
            fill_receiver_report(rtcp_reports.sr.sr.receiver, now);
            buf = &rtcp_reports.sr;
            len = rtcp_reports.sr.packet_length;
        } else {
            // SR without RR data
            fill_sender_report(rtcp_reports.sr_empty.sr.sender, now, user_ts);
            buf = &rtcp_reports.sr_empty;
            len = rtcp_reports.sr_empty.packet_length;
        }
    } else { // no data sent
        if (rtp_stats.current_rx && rtp_stats.current_rx->pkt) {
            // RR with data
            fill_receiver_report(rtcp_reports.rr.rr.receiver, now);
            buf = &rtcp_reports.rr;
            len = rtcp_reports.rr.packet_length;
        } else {
            // RR without data
            buf = &rtcp_reports.rr_empty;
            len = rtcp_reports.rr_empty.packet_length;
        }
    }

    rtp_stats.unlock();

    AmRtpPacket rp;
    rp.compile_raw((unsigned char *)buf, len);

    if (getEndpoint()->sendRtcp(&rp) < 0)
        return;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                   functions for job with attributes

void AmRtpStream::setTransport(TransProt trans)
{
    CLASS_DBG("set transport to: %d(%s)", trans, transport_p_2_str(trans).c_str());
    transport = trans; // local copy: reportable without the endpoint (e.g. for a disabled stream)
    sdpEndpoint()->setTransport(trans);
}

void AmRtpStream::clearRTPTimeout(struct timeval *recv_time)
{
    memcpy(&last_recv_time, recv_time, sizeof(struct timeval));
}

void AmRtpStream::clearRTPTimeout()
{
    gettimeofday(&last_recv_time, NULL);
}

int AmRtpStream::getDefaultPT()
{
    for (PayloadCollection::iterator it = payloads.begin(); it != payloads.end(); ++it) {
        // skip signaling payloads (telephone-event / comfort-noise)
        if (it->codec_id == CODEC_TELEPHONE_EVENT || it->codec_id == CODEC_CN)
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
    if (local_telephone_event_pt.get())
        return local_telephone_event_pt->payload_type;
    return -1;
}

bool AmRtpStream::isLocalTelephoneEventPayload(unsigned char payload)
{
    return test_bit(payload % BITS_PER_LONG, &local_telephone_event_payloads[payload >> _BITOPS_LONG_SHIFT]);
}

void AmRtpStream::setPayloadProvider(AmPayloadProvider *pl_prov)
{
    payload_provider = pl_prov;
}

void AmRtpStream::setReceiving(bool r)
{
    CLASS_DBG("set receiving=%s", r ? "true" : "false");
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

    flushReceiveBuffer();

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

void AmRtpStream::setRelayStream(AmRtpStream *stream)
{
    relay_stream = stream;
    CLASS_DBG("set relay stream [%p]", stream);
}

void AmRtpStream::setRelayPayloads(const PayloadMask &_relay_payloads)
{
    relay_payloads = _relay_payloads;
}

void AmRtpStream::setRelayPayloadMap(const PayloadRelayMap &_relay_map)
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
    getEndpoint()->setRawMode();
}

bool AmRtpStream::isRawRelay()
{
    return relay_raw;
}

void AmRtpStream::setRtpRelayTransparentSeqno(bool transparent)
{
    CLASS_DBG("%sabled RTP relay transparent seqno", transparent ? "en" : "dis");
    relay_transparent_seqno = transparent;
}

void AmRtpStream::setRtpRelayTransparentSSRC(bool transparent)
{
    CLASS_DBG("%sabled RTP relay transparent SSRC", transparent ? "en" : "dis");
    relay_transparent_ssrc = transparent;
}

void AmRtpStream::setRtpRelayFilterRtpDtmf(bool filter)
{
    CLASS_DBG("%sabled RTP relay filtering of RTP DTMF (2833 / 3744)", filter ? "en" : "dis");
    relay_filter_dtmf = filter;
}

void AmRtpStream::setRtpRelayTimestampAligning(bool enable_aligning)
{
    CLASS_DBG("%sabled RTP relay timestamp aligning", enable_aligning ? "en" : "dis");
    relay_timestamp_aligning = enable_aligning;
    if (relay_timestamp_aligning) {
        CLASS_DBG("relay_timestamp_aligning is deprecated because of using timestamp from media processor as reference "
                  "for relay");
    }
}

void AmRtpStream::setRtpForceRelayDtmf(bool relay)
{
    CLASS_DBG("%sabled force relay of RTP DTMF (2833 / 3744)", relay ? "en" : "dis");
    force_relay_dtmf = relay;
}

void AmRtpStream::setRtpForceRelayCN(bool relay)
{
    CLASS_DBG("%sabled force relay CN payload", relay ? "en" : "dis");
    force_relay_cn = relay;
}

void AmRtpStream::setRtpPing(bool enable)
{
    CLASS_DBG("%sabled RTP Ping", enable ? "en" : "dis");
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
    for (PayloadCollection::iterator it = payloads.begin(); it != payloads.end(); ++it) {
        if (it->pt == payload_type)
            return it->name;
    }

    // fall back to global registry
    if (payload_provider) {
        amci_payload_t *pl = payload_provider->payload(payload_type);
        if (pl && pl->name)
            return string(pl->name);
    }
    return string("");
}

bool AmRtpStream::isPayloadCN(int payload_type) const
{
    for (const auto &pl : payloads) {
        if (pl.pt == payload_type)
            return pl.codec_id == CODEC_CN;
    }
    return false;
}

///
AmMediaEndpoint *AmRtpStream::getEndpoint() const
{
    if (!endpoint) {
        endpoint = createEndpoint();
        session->addMediaEndpoint(endpoint);
    }
    return endpoint;
}

void AmRtpStream::flushReceiveBuffer()
{
    receive_mut.lock();
    for (auto &it : receive_buf)
        it.second->release();
    receive_buf.clear();
    while (!rtp_ev_qu.empty()) {
        rtp_ev_qu.front()->release();
        rtp_ev_qu.pop();
    }
    receive_mut.unlock();
}

void AmRtpStream::setEndpoint(AmMediaEndpoint *ep)
{
    if (endpoint == ep) {
        pending_endpoint = nullptr;
        return;
    }
    if (endpoint) {
        endpoint->stopReceiving();
    }
    flushReceiveBuffer();
    endpoint = ep;
    if (ep)
        ep->addMember(this);
    pending_endpoint = nullptr;
}

AmMediaEndpoint *AmRtpStream::releaseEndpoint()
{
    AmMediaEndpoint *e = endpoint;
    if (e) {
        e->stopReceiving();
        flushReceiveBuffer();
        e->removeMember(this);
    }
    endpoint = nullptr;
    return e;
}

void AmRtpStream::stopReceiving()
{
    if (endpoint)
        endpoint->stopReceiving();
}

void AmRtpStream::resumeReceiving()
{
    if (endpoint)
        endpoint->resumeReceiving();
}

void AmRtpStream::setLogger(msg_logger *_logger)
{
    CLASS_DBG("AmRtpStream: change logger to %p", _logger);
    if (endpoint)
        endpoint->setLogger(_logger);
}

void AmRtpStream::setSensor(msg_sensor *_sensor)
{
    CLASS_DBG("AmRtpStream: change sensor to %p", _sensor);
    if (endpoint)
        endpoint->setSensor(_sensor);
}

int AmRtpStream::getRPort(int type)
{
    return endpoint ? endpoint->getRPort(type) : 0;
}

string AmRtpStream::getRHost(int type)
{
    return endpoint ? endpoint->getRHost(type) : string();
}

void AmRtpStream::setRAddr(const string &addr, unsigned short port)
{
    if (endpoint)
        endpoint->setRAddr(addr, port);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                   help functions

void AmRtpStream::replaceAudioMediaParameters(SdpMedia &m, unsigned int idx, AddressType addr_type)
{
    getEndpoint()->setLocalIP(addr_type);

    auto *dlg = session ? session->dlg : nullptr;
    if (!dlg) {
        CLASS_DBG("no dlg");
        return;
    }

    bool rejected = (m.port == 0); // keep rejected media rejected

    m.rtcp_port = 0;
    m.rtcp_conn.address.clear();
    m.crypto.clear();
#ifdef WITH_ZRTP
    m.zrtp_hash.hash.clear();
    m.zrtp_hash.is_use = false;
#endif
    m.dir   = SdpMedia::DirUndefined;
    m.setup = S_UNDEFINED;
    m.ssrc  = l_ssrc;

    getEndpoint()->setIceStream(session ? session->isUseIceMediaStream() : false);

    switch (dlg->getOAState()) {
    case AmOfferAnswer::OA_None:
    case AmOfferAnswer::OA_OfferSent:
    case AmOfferAnswer::OA_Completed: getEndpoint()->fillSdpOffer(m); break;
    case AmOfferAnswer::OA_OfferRecved:
    {
        const auto &offer = dlg->getRemoteSdp();
        if (idx >= offer.media.size()) {
            CLASS_DBG("no stream with idx %d in offer media", idx);
            return;
        }
        getEndpoint()->fillSdpAnswer(offer.media[idx], m);
    } break;
    default: CLASS_ERROR("unexpected OA state %d in AmRtpStream::replaceAudioMediaParameters", dlg->getOAState());
    }

    if (rejected) { // restore the rejection
        m.port      = 0;
        m.rtcp_port = 0;
    }
}

void AmRtpStream::payloads_id2str(const vector<int> i, vector<string> &s)
{
    std::vector<int>::const_iterator it = i.begin();
    for (; it != i.end(); ++it) {
        std::string pname;
        pname = getPayloadName(*it);
        if (pname.empty()) {
            pname = int2str(*it);
        } else {
            transform(pname.begin(), pname.end(), pname.begin(), ::tolower);
        }
        s.push_back(pname);
    }
}

AmRtpStream::MediaStats::MediaStats()
    : time_start{ 0, 0 }
    , time_end{ 0, 0 }
    , dropped(0)
    , out_of_buffer_errors(0)
    , rtp_parse_errors(0)
    , srtp_decript_errors(0)
    , rtcp_rr_sent(0)
    , rtcp_rr_recv(0)
    , rtcp_sr_sent(0)
    , rtcp_sr_recv(0)
{
}

AmRtpStream::MediaStats::rtp_common::rtp_common()
    : ssrc(0)
    , pkt(0)
    , bytes(0)
    , total_lost(0)
{
    bzero(&addr, sizeof(addr));
}

AmRtpStream::MediaStats::rx_stat::rx_stat()
    : decode_errors(0)
{
}

void AmRtpStream::getMediaStats(MediaStats &s)
{
    auto &rx = s.rx;
    auto &tx = s.tx;

    s.rtt                  = rtp_stats.rtt;
    s.dropped              = getEndpoint()->getDroppedPackets();
    s.out_of_buffer_errors = getEndpoint()->getOutOfBufferErrors();
    s.rtp_parse_errors     = getEndpoint()->getRtpParseErrors();
    s.srtp_decript_errors  = getEndpoint()->getSrtpUnprotectErrors();
    memcpy(&s.time_start, &rtp_stats.start, sizeof(struct timeval));
    gettimeofday(&s.time_end, nullptr);

    s.rtcp_rr_sent = rtp_stats.rtcp_rr_sent;
    s.rtcp_rr_recv = rtp_stats.rtcp_rr_recv;

    s.rtcp_sr_sent = rtp_stats.rtcp_sr_sent;
    s.rtcp_sr_recv = rtp_stats.rtcp_sr_recv;

    for (auto &it : rtp_stats.rx) {
        MediaStats::rx_stat *rx_ssrc;
        unsigned int         ssrc = it.first;
        auto                 f_it = std::find_if(rx.begin(), rx.end(),
                                                 [ssrc](const struct MediaStats::rx_stat &s) -> bool { return s.ssrc == ssrc; });
        if (f_it != rx.end())
            rx_ssrc = &*f_it;
        else {
            rx.emplace_back();
            rx_ssrc = &rx.back();
        }

        // RX rtp_common
        rx_ssrc->ssrc       = ssrc;
        rx_ssrc->pkt        = it.second.pkt;
        rx_ssrc->bytes      = it.second.bytes;
        rx_ssrc->total_lost = it.second.loss;
        // RX specific
        rx_ssrc->rtcp_jitter   = it.second.rtcp_jitter_usec;
        rx_ssrc->delta         = it.second.rx_delta;
        rx_ssrc->jitter        = it.second.jitter_usec;
        rx_ssrc->decode_errors = it.second.decode_err;
        memcpy(&rx_ssrc->addr, &it.second.addr, sizeof(struct sockaddr_storage));
        payloads_id2str(incoming_payloads[it.first], rx_ssrc->payloads_transcoded);
        payloads_id2str(incoming_relayed_payloads[it.first], rx_ssrc->payloads_relayed);
    }


    // TX rtp_comon
    tx.ssrc = l_ssrc;
    if (!getEndpoint()->getLocalAddr(&tx.addr))
        memset(&tx.addr, 0, sizeof(struct sockaddr_storage));
    tx.pkt        = rtp_stats.tx.pkt;
    tx.bytes      = rtp_stats.tx.bytes;
    tx.total_lost = rtp_stats.tx.loss;
    payloads_id2str(outgoing_payloads, tx.payloads_transcoded);
    payloads_id2str(outgoing_relayed_payloads, tx.payloads_relayed);

    // TX specific
    tx.jitter = rtp_stats.rtcp_remote_jitter;

    // ICE phase/pair + DTLS handshake timings (per existing transport context)
    getEndpoint()->fillIceStats(s.ice);
    getEndpoint()->fillDtlsStats(s.dtls);
}


void AmRtpStream::debug()
{
#define BOOL_STR(b) ((b) ? "yes" : "no")

    sockaddr_storage la;
    if (endpoint && endpoint->getLocalAddr(&la)) {
        CLASS_DBG("\t<%i> <-> <%s:%i>", endpoint->getLocalPort(), getRHost(RTP_TRANSPORT).c_str(),
                  getRPort(RTP_TRANSPORT));
    } else {
        CLASS_DBG("\t<unbound> <-> <%s:%i>", getRHost(RTP_TRANSPORT).c_str(), endpoint ? endpoint->getLocalPort() : 0);
    }

    if (relay_enabled && relay_stream) {
        CLASS_DBG("\tinternal relay to stream %p (local port %i)", relay_stream,
                  relay_stream->endpoint ? relay_stream->endpoint->getLocalPort() : 0);
    } else {
        CLASS_DBG("\tno relay");
    }

    CLASS_DBG("\tmute: %s, sending: %s, receiving: %s", BOOL_STR(mute), BOOL_STR(sending), BOOL_STR(receiving));
#undef BOOL_STR
}

void AmRtpStream::getInfo(AmArg &ret)
{
    std::stringstream s;
    s << std::hex << this;
    ret["self_ptr"] = s.str();

    s.clear();
    ret["relay_enabled"]  = relay_enabled;
    ret["relay_raw"]      = relay_raw;
    ret["force_relay_cn"] = force_relay_cn;
    AmArg &p              = ret["relay_payloads"];
    for (auto &payload : payloads) {
        if (relay_payloads.get(payload.pt)) {
            AmArg pl;
            pl["encoding_name"] = payload.name;
            pl["payload_type"]  = payload.pt;
            pl["clock_rate"]    = (int)payload.clock_rate;
            p.push(pl);
        }
    }
    if (relay_stream) {
        std::stringstream s;
        s << std::hex << relay_stream;
        ret["relay_ptr"] = s.str();
    } else {
        ret["relay_ptr"] = "nullptr";
    }

    ret["sdp_media_index"] = sdp_media_index;
    ret["l_ssrc"]          = int2hex(l_ssrc);

    if (endpoint)
        endpoint->getInfo(ret);
    else
        ret["socket"] = "unbound";

    ret["mute"]      = mute;
    ret["sending"]   = sending;
    ret["receiving"] = receiving;
}

void AmRtpStream::update_sender_stats(const AmRtpPacket &p)
{
    AmLock l(rtp_stats);

    // struct timeval now;

    // gettimeofday(&now, nullptr);

    rtp_stats.rtp_tx_last_ts  = p.timestamp;
    rtp_stats.rtp_tx_last_seq = p.sequence;

    RtcpUnidirectionalStat &s = rtp_stats.tx;

    // s.update = now;
    // s.update_cnt++;

    s.pkt++;
    s.bytes += p.getDataSize();
}

void AmRtpStream::fill_sender_report(RtcpSenderReportHeader &s, struct timeval &now, unsigned int user_ts)
{
    uint64_t i;

    rtp_stats.rtcp_sr_sent++;

    s.sender_pcount = htonl(rtp_stats.tx.pkt);
    s.sender_bcount = htonl(rtp_stats.tx.bytes);
    s.rtp_ts        = htonl(user_ts);

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
    CLASS_DBG("init_receiver_info");
    r_ssrc = p.ssrc;
    rtcp_reports.update(r_ssrc);
    r_ssrc_i = true;

    rtp_stats.probation = MIN_SEQUENTIAL;
    rtp_stats.init_seq(p.ssrc, p.sequence);
}

void AmRtpStream::update_receiver_stats(const AmRtpPacket &p)
{
    AmLock l(rtp_stats);

    if ((!r_ssrc_i) || (p.ssrc != r_ssrc)) {
        if (rtp_stats.current_rx)
            rtp_stats.current_rx->loss += rtp_stats.total_lost;
        init_receiver_info(p);
    }

    if (rtp_stats.current_rx) {
        memccpy(&rtp_stats.current_rx->addr, &p.saddr, 1, sizeof(struct sockaddr_storage));
        rtp_stats.current_rx->pkt++;
        rtp_stats.current_rx->bytes += p.getDataSize();
    }

    if (!rtp_stats.update_seq(p.ssrc, p.sequence)) {
        /* skip jitter measurement
           for duplicated/reordered/unexpected sequence packets */
        return;
    }

    // https://tools.ietf.org/html/rfc3550#appendix-A.8
    uint64_t recv_time_msec = p.recv_time.tv_sec * 1000 + p.recv_time.tv_usec / 1000;
    int      transit        = (recv_time_msec << 3) - p.timestamp;
    if (rtp_stats.transit) {
        int d = rtp_stats.transit - transit;
        if (d < 0)
            d = -d;
        if (rtp_stats.current_rx)
            rtp_stats.current_rx->rtcp_jitter += d - ((rtp_stats.current_rx->rtcp_jitter + 8) >> 4);
    }
    rtp_stats.transit = transit;

    if (timerisset(&rtp_stats.rx_recv_time)) {
        timeval diff;
        timersub(&p.recv_time, &rtp_stats.rx_recv_time, &diff);
        if (rtp_stats.current_rx) {
            auto &rx_delta = rtp_stats.current_rx->rx_delta;
            rx_delta.update((diff.tv_sec * 1000000) + diff.tv_usec);
            if (rx_delta.n && (0 == rx_delta.n % 250)) {
                // update jitter every 250 packets (5 seconds)
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

    if (rtp_stats.sr_lsr) {
        r.lsr = htonl(rtp_stats.sr_lsr);

        timersub(&now, &rtp_stats.sr_recv_time, &delay);
        r.dlsr = (delay.tv_sec << 16);
        r.dlsr |= (uint16_t)(delay.tv_usec * 65536 / 1e6);
        r.dlsr = htonl(r.dlsr);
    } else {
        r.lsr  = 0;
        r.dlsr = 0;
    }

    uint32_t jitter = rtp_stats.current_rx->rtcp_jitter >> 4;
    r.jitter        = htonl(jitter);

    // update stats
    rtp_stats.current_rx->rtcp_jitter_usec.update(jitter);
}

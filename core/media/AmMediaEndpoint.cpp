/*
 * AmMediaEndpoint - transport set + ICE/DTLS/ZRTP contexts + inbound receive/demux.
 * See AmMediaEndpoint.h. Logic moved here from AmRtpStream during the endpoint refactor.
 */
#include "AmMediaEndpoint.h"
#include "AmRtpStream.h"
#include "AmSession.h"
#include "AmLcConfig.h"
#include "AmSrtpConnection.h"
#include "sip/ip_util.h"

#include <algorithm>
#include <cstring>

#define BIND_ATTEMPTS_COUNT 10
#define ICE_PWD_SIZE        22
#define ICE_UFRAG_SIZE      4

AmMediaEndpoint::AmMediaEndpoint(AmRtpStream *s, AmSession *sess, int iface)
    : streams{ s }
    , session(sess)
    , l_if(iface)
    , transport(TP_RTPAVP)
    , multiplexing(sess ? sess->isRtcpMultiplexing() : false)
    , connection_is_muted(false)
    , relay_is_muted(false)
    , symmetric_rtp_enable(false)
    , symmetric_rtp_endless(sess ? sess->getRtpEndlessSymmetricRtp() : false)
    , dropped_packets_count(0)
    , incoming_bytes(0)
    , rtp_parse_errors(0)
    , out_of_buffer_errors(0)
    , srtp_unprotect_errors(0)
    , is_ice_stream(false)
    , ice_controlled(false)
    , ssl_key_log_file(nullptr)
    , cur_rtp_trans(nullptr)
    , cur_rtcp_trans(nullptr)
    , media_established_fired(false)
    , raw_mode(false)
    , media_setup_start(std::chrono::steady_clock::now())
{
    assert(s); // an endpoint is always created by its (primary) stream, so streams.front() stays valid
    ((uint32_t *)&ice_tiebreaker)[0] = get_random();
    ((uint32_t *)&ice_tiebreaker)[1] = get_random();
#ifdef WITH_ZRTP
    zrtp_context.addSubscriber(this);
#endif
}

AmMediaEndpoint::~AmMediaEndpoint()
{
    for (int i = 0; i < MAX_TRANSPORT_TYPE; i++) {
        if (ice_context[i])
            ice_context[i]->destroyContext();
    }
    iterateTransports([](auto tr) { delete tr; });
    for (int i = 0; i < MAX_TRANSPORT_TYPE; i++)
        ice_context[i].reset(nullptr);
    ip4_transports.clear();
    ip6_transports.clear();
    if (ssl_key_log_file)
        dec_ref(ssl_key_log_file);
}

void AmMediaEndpoint::iterateTransports(std::function<void(AmMediaTransport *)> it)
{
    for (auto tr : ip4_transports)
        it(tr);
    for (auto tr : ip6_transports)
        it(tr);
}

void AmMediaEndpoint::calcRtpPorts(AmMediaTransport *tr_rtp, AmMediaTransport *tr_rtcp)
{
    assert(tr_rtp);

    if (tr_rtp->getLocalPort() && tr_rtcp && tr_rtcp->getLocalPort())
        return;

    sockaddr_storage l_rtcp_addr, l_rtp_addr;
    int              retry = BIND_ATTEMPTS_COUNT;
    for (; retry; --retry) {

        if (!tr_rtp->getLocalSocket() || (tr_rtcp && !tr_rtcp->getLocalSocket())) {
            return;
        }

        if (!AmConfig.getMediaProtoInfo(tr_rtp->getLocalIf(), tr_rtp->getLocalProtoId()).getNextRtpAddress(l_rtp_addr))
        {
            CLASS_ERROR("no free RTP ports");
            throw AmSession::NoFreeRtpPortsException();
        }

        if (tr_rtp != tr_rtcp && tr_rtcp) {
            memcpy(&l_rtcp_addr, &l_rtp_addr, sizeof(sockaddr_storage));
            am_set_port(&l_rtcp_addr, am_get_port(&l_rtp_addr) + 1);

            if (bind(tr_rtcp->getLocalSocket(), (const struct sockaddr *)&l_rtcp_addr, SA_len(&l_rtcp_addr))) {
                CLASS_ERROR("failed to bind port %d for RTCP: %s", am_get_port(&l_rtp_addr) + 1, strerror(errno));
                goto try_another_port;
            }
        }

        if (bind(tr_rtp->getLocalSocket(), (const struct sockaddr *)&l_rtp_addr, SA_len(&l_rtp_addr))) {
            CLASS_ERROR("failed to bind port %hu for RTP: %s", am_get_port(&l_rtp_addr), strerror(errno));
            goto try_another_port;
        }

        tr_rtp->setLocalAddr(&l_rtp_addr);
        if (tr_rtp != tr_rtcp && tr_rtcp) {
            tr_rtcp->setLocalAddr(&l_rtcp_addr);
        }
        break;

    try_another_port:
        AmConfig.getMediaProtoInfo(tr_rtp->getLocalIf(), tr_rtp->getLocalProtoId()).freeRtpAddress(l_rtp_addr);

        tr_rtp->getLocalSocket(true);
        if (tr_rtp != tr_rtcp && tr_rtcp) {
            tr_rtcp->getLocalSocket(true);
        }
    }

    if (!retry) {
        ERROR("could not bind RTP/RTCP ports considered free after %d attempts", BIND_ATTEMPTS_COUNT);
        throw string("could not find a free RTP port");
    }
}

void AmMediaEndpoint::initIP4Transport()
{
    if (!ip4_transports.empty())
        return;

    int proto_id = AmConfig.media_ifs[l_if].findProto(AT_V4, MEDIA_info::RTP);
    if (proto_id < 0) {
        CLASS_ERROR("AmMediaEndpoint: missed requested IPv4 proto in the chosen media interface %d", l_if);
        return;
    }

    AmMediaTransport *rtp = new AmMediaTransport(this, l_if, proto_id, RTP_TRANSPORT), *rtcp = nullptr;
    ip4_transports.push_back(rtp);
    if (!multiplexing) {
        rtcp = new AmMediaTransport(this, l_if, proto_id, RTCP_TRANSPORT);
        ip4_transports.push_back(rtcp);
    }
    calcRtpPorts(rtp, rtcp);
}

void AmMediaEndpoint::initIP6Transport()
{
    if (!ip6_transports.empty())
        return;

    int proto_id = AmConfig.media_ifs[l_if].findProto(AT_V6, MEDIA_info::RTP);
    if (proto_id < 0) {
        CLASS_ERROR("AmMediaEndpoint: missed requested IPv6 proto in the chosen media interface %d", l_if);
        return;
    }

    AmMediaTransport *rtp = new AmMediaTransport(this, l_if, proto_id, RTP_TRANSPORT), *rtcp = nullptr;
    ip6_transports.push_back(rtp);
    if (!multiplexing) {
        rtcp = new AmMediaTransport(this, l_if, proto_id, RTCP_TRANSPORT);
        ip6_transports.push_back(rtcp);
    }
    calcRtpPorts(rtp, rtcp);
}

void AmMediaEndpoint::setCurrentTransport(AmMediaTransport *tr)
{
    if (!tr)
        return;
    if (tr->getTransportType() == RTP_TRANSPORT || tr->getTransportType() == FAX_TRANSPORT) {
        cur_rtp_trans = tr;
        if (!cur_rtcp_trans && multiplexing)
            cur_rtcp_trans = tr;
    } else if (tr->getTransportType() == RTCP_TRANSPORT) {
        cur_rtcp_trans = tr;
    }
}

void AmMediaEndpoint::setLocalIP(AddressType addrtype)
{
    if (l_if < 0) {
        if (session)
            l_if = session->getRtpInterface();
        else {
            CLASS_ERROR("BUG: no session when initializing media endpoint, invalid interface can be used");
            l_if = 0;
        }
    }

    if (addrtype == AT_NONE)
        if (session)
            addrtype = session->getLocalMediaAddressType();

    vector<AmMediaTransport *> *transports;
    if (addrtype == AT_V4) {
        initIP4Transport();
        transports = &ip4_transports;
    } else {
        initIP6Transport();
        transports = &ip6_transports;
    }

    for (auto tr : *transports) {
        if (tr->getTransportType() == RTP_TRANSPORT || tr->getTransportType() == FAX_TRANSPORT)
            cur_rtp_trans = tr;
        else if (tr->getTransportType() == RTCP_TRANSPORT)
            cur_rtcp_trans = tr;
    }

    if (!cur_rtp_trans) {
        CLASS_ERROR("AmMediaEndpoint:setLocalIP on the interface(%d): failed to get transport for the address type %s",
                    l_if, addr_t_2_str(addrtype).c_str());
        string error("failed to get transport for the address type: ");
        error += addr_t_2_str(addrtype);
        throw error;
    }

    if (!cur_rtcp_trans)
        cur_rtcp_trans = cur_rtp_trans;
}

std::string AmMediaEndpoint::getLocalIP()
{
    if (!cur_rtp_trans || !cur_rtcp_trans)
        setLocalIP();
    return cur_rtp_trans->getLocalIP();
}

std::string AmMediaEndpoint::getLocalAddress()
{
    if (!cur_rtp_trans || !cur_rtcp_trans)
        setLocalIP();

    return cur_rtp_trans->getLocalAddress();
}

int AmMediaEndpoint::getLocalPort()
{
    if (!cur_rtp_trans || !cur_rtcp_trans)
        setLocalIP();
    return cur_rtp_trans->getLocalPort();
}

int AmMediaEndpoint::getLocalRtcpPort()
{
    if (!cur_rtp_trans || !cur_rtcp_trans)
        setLocalIP();
    return cur_rtcp_trans->getLocalPort();
}

void AmMediaEndpoint::setRAddr(const string &addr, unsigned short port)
{
    if (isIceStream())
        return;

    CLASS_DBG("RTP remote address set to %s:%u", addr.c_str(), port);

    sockaddr_storage raddr, laddr;
    am_inet_pton(addr.c_str(), &raddr);
    if (!cur_rtp_trans)
        return;

    cur_rtp_trans->getLocalAddr(&laddr);
    if (laddr.ss_family == raddr.ss_family)
        cur_rtp_trans->setRAddr(addr, port);
}

int AmMediaEndpoint::getRPort(int type)
{
    if (type == RTCP_TRANSPORT && cur_rtcp_trans)
        return cur_rtcp_trans->getRPort(true);
    else if ((type == RTP_TRANSPORT || type == FAX_TRANSPORT) && cur_rtp_trans)
        return cur_rtp_trans->getRPort(false);
    return 0;
}

string AmMediaEndpoint::getRHost(int type)
{
    if (type == RTCP_TRANSPORT && cur_rtcp_trans)
        return cur_rtcp_trans->getRHost(true);
    else if ((type == RTP_TRANSPORT || type == FAX_TRANSPORT) && cur_rtp_trans)
        return cur_rtp_trans->getRHost(false);
    return "";
}

void AmMediaEndpoint::setPassiveMode(bool p)
{
    if (p && !is_ice_stream)
        symmetric_rtp_enable = true;

    iterateTransports([&](auto tr) { tr->setPassiveMode(p); });
}

// fill the transport-level part of an SDP media line (addresses/ports/proto/mux/crypto/setup/ICE).
// the media-level part (direction, payloads, ssrc, bundle) is filled by the stream.
void AmMediaEndpoint::fillSdpOffer(SdpMedia &m)
{
    m.is_multiplex = isMultiplexing();
    m.port         = getLocalPort();
    m.rtcp_port    = m.is_multiplex ? 0 : getLocalRtcpPort();
    m.nports       = 0;
    m.transport    = transport;
    m.cname        = getLocalAddress();

    if (cur_rtp_trans)
        cur_rtp_trans->getSdpOffer(m);

    applyIceParams(m);
}

void AmMediaEndpoint::fillSdpAnswer(const SdpMedia &offer, SdpMedia &answer)
{
    answer.is_multiplex = isMultiplexing();
    answer.port         = getLocalPort();
    answer.rtcp_port    = answer.is_multiplex ? 0 : getLocalRtcpPort();
    answer.nports       = 0;
    answer.transport    = transport;
    answer.cname        = getLocalAddress();

    if (cur_rtp_trans)
        cur_rtp_trans->getSdpAnswer(offer, answer);

    applyIceParams(answer);
}

int AmMediaEndpoint::sendRtp(AmRtpPacket *p, AmStreamConnection::ConnectionType type)
{
    return cur_rtp_trans ? cur_rtp_trans->send(p, type) : 0;
}

int AmMediaEndpoint::sendRtcp(AmRtpPacket *p)
{
    if (!cur_rtcp_trans)
        return 0;
    int res = cur_rtcp_trans->send(p, AmStreamConnection::RTCP_CONN);
    if (res < 0) {
        CLASS_ERROR("failed to send RTCP packet: errno: %d, fd: %d, raddr: %s:%d, len: %d", errno,
                    cur_rtcp_trans->getLocalSocket(), cur_rtcp_trans->getRHost(true).c_str(),
                    cur_rtcp_trans->getRPort(true), p->getBufferSize());
    }
    return res;
}

int AmMediaEndpoint::sendUdptl(AmRtpPacket *p)
{
    return cur_rtp_trans ? cur_rtp_trans->send(p, AmStreamConnection::UDPTL_CONN) : 0;
}

void AmMediaEndpoint::setRawMode()
{
    if (streams.size() > 1) {
        CLASS_ERROR("BUG: refusing to switch a bundled media endpoint to raw mode (streams=%zu)", streams.size());
        return;
    }
    raw_mode = true;
    if (cur_rtp_trans)
        cur_rtp_trans->setMode(AmMediaTransport::TRANSPORT_MODE_RAW);
}

void AmMediaEndpoint::stopReceiving()
{
    iterateTransports([](auto tr) { tr->stopReceiving(); });
}

void AmMediaEndpoint::resumeReceiving()
{
    iterateTransports([](auto tr) { tr->resumeReceiving(); });
}

void AmMediaEndpoint::setLogger(msg_logger *l)
{
    iterateTransports([&](auto tr) { tr->setLogger(l); });
}

void AmMediaEndpoint::setSensor(msg_sensor *s)
{
    iterateTransports([&](auto tr) { tr->setSensor(s); });
}

bool AmMediaEndpoint::isZrtpEnabled() const
{
    return session && session->isZrtpEnabled();
}

// one entry per existing transport context (FAX folds into the RTP slot)
void AmMediaEndpoint::fillIceStats(std::vector<IceContextStat> &out)
{
    for (int t = 0; t < MAX_TRANSPORT_TYPE; t++) {
        if (!ice_context[t])
            continue;
        out.emplace_back();
        ice_context[t]->fillStat(out.back());
    }
}

void AmMediaEndpoint::fillDtlsStats(std::vector<DtlsHandshakeStat> &out)
{
    for (int t = 0; t < MAX_TRANSPORT_TYPE; t++) {
        if (!dtls_context[t])
            continue;
        DtlsHandshakeStat ds;
        dtls_context[t]->getDtlsStat(ds);
        if (!timerisset(&ds.t_start))
            continue;
        ds.transport_type = t;
        out.push_back(ds);
    }
}

void AmMediaEndpoint::update_sender_stats(const AmRtpPacket &p)
{
    getStream(&p)->update_sender_stats(p);
}

void AmMediaEndpoint::setMute(bool mute)
{
    for (auto *s : streams)
        s->setMute(mute);
}

void AmMediaEndpoint::fillTransportsInfo(AmArg &transports)
{
    for (auto &t : ip4_transports) {
        AmArg trsp;
        trsp["protocol"] = "ip4";
        t->getInfo(trsp);
        transports.push(trsp);
    }
    for (auto &t : ip6_transports) {
        AmArg trsp;
        trsp["protocol"] = "ip6";
        t->getInfo(trsp);
        transports.push(trsp);
    }
}

void AmMediaEndpoint::getInfo(AmArg &ret)
{
    sockaddr_storage la;
    if (getLocalAddr(&la)) {
        AmArg &a         = ret["socket"];
        a["local_ip"]    = getLocalIP();
        a["local_port"]  = getLocalPort();
        a["remote_host"] = getRHost(RTP_TRANSPORT);
        a["remote_port"] = getRPort(RTP_TRANSPORT);
    } else {
        ret["socket"] = "unbound";
    }

    fillTransportsInfo(ret["transports"]);
}

bool AmMediaEndpoint::getLocalAddr(sockaddr_storage *a)
{
    if (!cur_rtp_trans)
        return false;
    cur_rtp_trans->getLocalAddr(a);
    return true;
}

void AmMediaEndpoint::getRAddr(sockaddr_storage *a)
{
    if (cur_rtp_trans)
        cur_rtp_trans->getRAddr(a);
}

void AmMediaEndpoint::getRAddr(int type, sockaddr_storage *a)
{
    if (type == RTCP_TRANSPORT && cur_rtcp_trans)
        cur_rtcp_trans->getRAddr(true, a);
    else if ((type == RTP_TRANSPORT || type == FAX_TRANSPORT) && cur_rtp_trans)
        cur_rtp_trans->getRAddr(false, a);
}

//
// --- ICE / DTLS / ZRTP contexts ---
//

void AmMediaEndpoint::onSrtpKeysAvailable(int transport_type, uint16_t srtp_profile, const string &local_key,
                                          const string &remote_key)
{
    CLASS_DBG("onSrtpKeysAvailable() endpoint:%p, transport:%d", to_void(this), transport_type);
    iterateTransports([&](auto tr) {
        if (!tr->isSrtpEnable())
            return;
        tr->onSrtpKeysAvailable(transport_type, srtp_profile, local_key, remote_key);
    });
}

void AmMediaEndpoint::onCloseDtlsSession(uint8_t transport_type)
{
    iterateTransports([&](auto tr) {
        if (tr->getTransportType() != transport_type)
            return;
        tr->onCloseDtlsSession();
    });
}

void AmMediaEndpoint::initIce()
{
    if (!ice_context[RTP_TRANSPORT])
        ice_context[RTP_TRANSPORT].reset(new IceContext(this, RTP_TRANSPORT));
    if (!ice_context[RTCP_TRANSPORT] && !multiplexing)
        ice_context[RTCP_TRANSPORT].reset(new IceContext(this, RTCP_TRANSPORT));
}

void AmMediaEndpoint::applyIceParams(SdpMedia &sdp_media)
{
    if (is_ice_stream) {
        initIP4Transport();
        initIP6Transport();

        sdp_media.is_ice = true;
        if (ice_pwd.empty()) {
            string data = AmSrtpConnection::gen_base64(ICE_PWD_SIZE);
            ice_pwd.clear();
            ice_pwd.append(data.begin(), data.begin() + ICE_PWD_SIZE);
        }
        sdp_media.ice_pwd = ice_pwd;
        if (ice_ufrag.empty()) {
            string data = AmSrtpConnection::gen_base64(ICE_UFRAG_SIZE);
            ice_ufrag.clear();
            ice_ufrag.append(data.begin(), data.begin() + ICE_UFRAG_SIZE);
        }
        sdp_media.ice_ufrag = ice_ufrag;

        iterateTransports([&](auto tr) {
            SdpIceCandidate candidate;
            tr->prepareIceCandidate(candidate);
            sdp_media.ice_candidate.push_back(candidate);
        });
    } else {
        sdp_media.is_ice = false;
        sdp_media.ice_pwd.clear();
        sdp_media.ice_ufrag.clear();
        sdp_media.ice_candidate.clear();
    }
}

// entry points below are called from non-session threads (rtp receiver, stun processor, media processor):
// connection creation errors are logged here, nobody above can handle them

void AmMediaEndpoint::allowStunConnection(AmMediaTransport *t, sockaddr_storage *remote_addr, int priority)
{
    try {
        iterateTransports([&](auto tr) {
            if (t->getTransportType() != tr->getTransportType())
                return;
            tr->allowStunConnection(remote_addr, priority);
        });
    } catch (const string &error) {
        CLASS_ERROR("allowStunConnection: %s", error.c_str());
    }
    setCurrentTransport(getIceContext(t->getTransportType())->getCurrentTransport());
    setMute(cur_rtp_trans->isMute(AmStreamConnection::RAW_CONN));
}

void AmMediaEndpoint::allowStunPair(AmMediaTransport *t, sockaddr_storage *remote_addr)
{
    onLeavePassiveMode();
    onRtpEndpointLearned();

    try {
        iterateTransports([&](auto tr) {
            if (t->getTransportType() != tr->getTransportType())
                return;
            tr->allowStunPair(remote_addr);
        });
    } catch (const string &error) {
        CLASS_ERROR("allowStunPair: %s", error.c_str());
    }
    setCurrentTransport(t);
}

void AmMediaEndpoint::dtlsSessionActivated(AmMediaTransport *t, uint16_t srtp_profile, const vector<uint8_t> &local_key,
                                           const vector<uint8_t> &remote_key)
{
    if (cur_rtp_trans != t) {
        cur_rtp_trans = t;
        if (multiplexing)
            cur_rtcp_trans = t;
    }

    string l_key(local_key.size(), 0), r_key(remote_key.size(), 0);
    memcpy((void *)l_key.c_str(), local_key.data(), local_key.size());
    memcpy((void *)r_key.c_str(), remote_key.data(), remote_key.size());
    try {
        onSrtpKeysAvailable(t->getTransportType(), srtp_profile, l_key, r_key);
    } catch (const string &error) {
        CLASS_ERROR("dtlsSessionActivated: %s", error.c_str());
    }
}

void AmMediaEndpoint::onIceRoleConflict()
{
    ice_controlled                   = !ice_controlled;
    ((uint32_t *)&ice_tiebreaker)[0] = get_random();
    ((uint32_t *)&ice_tiebreaker)[1] = get_random();
}

bool AmMediaEndpoint::isIceControlled()
{
    return ice_controlled;
}
uint64_t AmMediaEndpoint::getIceTieBreaker()
{
    return ice_tiebreaker;
}

DtlsContext *AmMediaEndpoint::getDtlsContext(uint8_t transport_type)
{
    assert(transport_type < MAX_TRANSPORT_TYPE);
    if (transport_type == FAX_TRANSPORT)
        transport_type = RTP_TRANSPORT;
    return dtls_context[transport_type].get();
}

IceContext *AmMediaEndpoint::getIceContext(uint8_t transport_type)
{
    assert(transport_type < MAX_TRANSPORT_TYPE);
    if (transport_type == FAX_TRANSPORT)
        transport_type = RTP_TRANSPORT;
    return ice_context[transport_type].get();
}

void AmMediaEndpoint::setSklfile(SSLKeyLogger *logger)
{
    if (ssl_key_log_file)
        dec_ref(ssl_key_log_file);
    if (logger)
        inc_ref(logger);
    ssl_key_log_file = logger;
}

void AmMediaEndpoint::initDtls(uint8_t transport_type, bool client)
{
    MEDIA_interface &media_if = AmConfig.getMediaIfaceInfo(l_if);
    if (!media_if.srtp->dtls_enable)
        throw string("DTLS is not configured on: ") + media_if.name;
    std::shared_ptr<dtls_conf> dtls_settings;
    if (client)
        dtls_settings = std::make_shared<dtls_conf>(&media_if.srtp->client_settings);
    else
        dtls_settings = std::make_shared<dtls_conf>(&media_if.srtp->server_settings);
    AmMediaTransport *tr = (transport_type == RTCP_TRANSPORT) ? cur_rtcp_trans : cur_rtp_trans;
    assert(tr);
    getDtlsContext(transport_type)->initContext(tr->getLocalIP(), tr->getLocalPort(), dtls_settings);
}

#ifdef WITH_ZRTP
extern "C" {
#include <bzrtp/bzrtp.h>
}

void AmMediaEndpoint::zrtpSessionActivated(srtp_profile_t srtp_profile, const vector<uint8_t> &local_key,
                                           const vector<uint8_t> &remote_key)
{
    string l_key(local_key.size(), 0), r_key(remote_key.size(), 0);
    memcpy((void *)l_key.c_str(), local_key.data(), local_key.size());
    memcpy((void *)r_key.c_str(), remote_key.data(), remote_key.size());
    try {
        onSrtpKeysAvailable(RTP_TRANSPORT, srtp_profile, l_key, r_key);
    } catch (const string &error) {
        CLASS_ERROR("zrtpSessionActivated: %s", error.c_str());
    }
}

void AmMediaEndpoint::initZrtp()
{
    MEDIA_interface &media_if = AmConfig.getMediaIfaceInfo(l_if);
    // first ZRTP channel keyed by the tag (primary) SSRC.
    // TODO(bundle-zrtp): for a BUNDLE (RFC 9143) over ZRTP, add one bzrtp channel per member SSRC
    // (bzrtp_addChannel + startChannelEngine, multistream per RFC 6189) instead of only the tag's.
    zrtp_context.createContext(streams.front()->get_ssrc());
    zrtp_context.setCryptoTypes(ZRTP_HASH_TYPE, media_if.srtp->zrtp_hashes);
    zrtp_context.setCryptoTypes(ZRTP_CIPHERBLOCK_TYPE, media_if.srtp->zrtp_ciphers);
    zrtp_context.setCryptoTypes(ZRTP_AUTHTAG_TYPE, media_if.srtp->zrtp_authtags);
    zrtp_context.setCryptoTypes(ZRTP_KEYAGREEMENT_TYPE, media_if.srtp->zrtp_dhmodes);
    zrtp_context.setCryptoTypes(ZRTP_SAS_TYPE, media_if.srtp->zrtp_sas);
    zrtp_context.init();
}

void AmMediaEndpoint::startZrtp()
{
    zrtp_context.start();
}

int AmMediaEndpoint::send_zrtp(unsigned char *buffer, unsigned int size)
{
    if (streams.front()->mute || !streams.front()->sending)
        return 0;

    AmRtpPacket rp;
    rp.compile_raw(buffer, size);
    sockaddr_storage raddr;
    cur_rtp_trans->getRAddr(false, &raddr);
    if (cur_rtp_trans && cur_rtp_trans->send(&raddr, buffer, size, AmStreamConnection::ZRTP_CONN) < 0) {
        CLASS_ERROR("while sending ZRTP packet.");
        return -1;
    }

    return size;
}
#endif /*WITH_ZRTP*/

// a=bundle-only marker (R1 will make it a typed SdpMedia field; until then scan generic attributes)
static bool is_bundle_only(const SdpMedia &m)
{
    for (const auto &a : m.attributes)
        if (a.attribute == "bundle-only")
            return true;
    return false;
}

int AmMediaEndpoint::init(const AmSdp &local, const AmSdp &remote, int media_index, bool sdp_offer_owner,
                          bool force_passive_mode, string &init_error)
{
    clearEstablished();

    const SdpMedia &local_media  = local.media[media_index];
    const SdpMedia &remote_media = remote.media[media_index];

    connection_is_muted = false;
    relay_is_muted      = false;

    if (!cur_rtp_trans) {
        CLASS_ERROR("AmMediaEndpoint::init. failed to get transport");
        init_error = "failed to get transport";
        return -1;
    }

    // a=bundle-only / rejected (port 0): no transport params - the tagged member sets up the shared
    // transport, this member just attaches. Nothing to init here.
    if (remote_media.port == 0 || is_bundle_only(remote_media) || is_bundle_only(local_media))
        return 0;

    if ((local_media.is_simple_srtp() && !remote_media.is_simple_srtp()) ||
        (local_media.is_dtls_srtp() && !remote_media.is_dtls_srtp()) ||
        (local_media.is_simple_rtp() && !remote_media.is_simple_rtp()) ||
        (local_media.is_dtls_udptl() && !remote_media.is_dtls_udptl()) ||
        (local_media.is_udptl() && !remote_media.is_udptl()))
    {
        CLASS_ERROR("AmMediaEndpoint::init. incompatible transport");
        init_error = "incompatible transport";
        return -1;
    }

    string address      = remote_media.conn.address.empty() ? remote.conn.address : remote_media.conn.address;
    int    port         = static_cast<int>(remote_media.port);
    string rtcp_address = remote_media.rtcp_conn.address.empty() ? address : remote_media.rtcp_conn.address;
    int    rtcp_port =
        static_cast<int>(remote_media.rtcp_port ? remote_media.rtcp_port : (multiplexing ? 0 : remote_media.port + 1));

    try {
        {
            srtp_fingerprint_p fingerprint(remote_media.fingerprint.hash, remote_media.fingerprint.value);
            bool               is_client = false;
            if (local_media.setup == S_ACTIVE || remote_media.setup == S_PASSIVE)
                is_client = true;
            else if (local_media.setup == S_PASSIVE || remote_media.setup == S_ACTIVE)
                is_client = false;

            if (local_media.is_dtls_srtp() && AmConfig.enable_srtp) {
                if (!dtls_context[RTP_TRANSPORT])
                    dtls_context[RTP_TRANSPORT].reset(new RtpSecureContext(this, fingerprint, is_client));
                if (!dtls_context[RTCP_TRANSPORT])
                    dtls_context[RTCP_TRANSPORT].reset(new RtpSecureContext(this, fingerprint, is_client));
            } else if (local_media.is_dtls_udptl()) {
                if (!dtls_context[RTP_TRANSPORT])
                    dtls_context[RTP_TRANSPORT].reset(new RtpSecureContext(this, fingerprint, is_client));
            }
        }
#ifdef WITH_ZRTP
        if (isZrtpEnabled() && AmConfig.enable_srtp && remote_media.zrtp_hash.is_use)
            zrtp_context.setRemoteHash(remote_media.zrtp_hash.hash);
#endif

        AmMediaStateArgs args;

        if (remote_media.is_use_ice() && is_ice_stream) {
            initIce();
            bool need_restart = !(ice_remote_ufrag == remote_media.ice_ufrag && ice_remote_pwd == remote_media.ice_pwd);
            if (need_restart) {
                ice_controlled   = sdp_offer_owner;
                ice_remote_ufrag = remote_media.ice_ufrag;
                ice_remote_pwd   = remote_media.ice_pwd;

                getIceContext(RTP_TRANSPORT)->reset();
                if (!multiplexing)
                    getIceContext(RTCP_TRANSPORT)->reset();
            }
            iterateTransports([&](auto tr) {
                CLASS_DBG("init ice endpoint:%p, state:%s", to_void(this), tr->state2str());
                auto conn_factory    = tr->getConnFactory();
                args.candidates      = &remote_media.ice_candidate;
                args.sdp_offer_owner = sdp_offer_owner;
                args.need_restart    = need_restart;
                args.udptl           = (local_media.is_dtls_udptl() || local_media.is_udptl());
                conn_factory->store_ice_cred(local_media, remote_media);
                if (tr->isSrtpEnable() && local_media.is_simple_srtp())
                    conn_factory->store_srtp_cred(local_media, remote_media);
                tr->template updateState<AmMediaIceState>(args);
            });
            getIceContext(RTP_TRANSPORT)->initContext();
            if (!multiplexing)
                getIceContext(RTCP_TRANSPORT)->initContext();
        } else if (local_media.is_simple_srtp() && AmConfig.enable_srtp) {
            MEDIA_interface &media_if = AmConfig.getMediaIfaceInfo(l_if);
            if (!media_if.srtp->srtp_enable)
                throw string("SRTP is not configured on: ") + media_if.name;
            args.address = address;
            args.port    = port;
            cur_rtp_trans->getConnFactory()->store_srtp_cred(local_media, remote_media);
            cur_rtp_trans->updateState<AmMediaSrtpState>(args);
            if (cur_rtcp_trans != cur_rtp_trans) {
                args.address = rtcp_address;
                args.port    = rtcp_port;
                cur_rtcp_trans->getConnFactory()->store_srtp_cred(local_media, remote_media);
                cur_rtcp_trans->updateState<AmMediaSrtpState>(args);
            }
            connection_is_muted = cur_rtp_trans->isMute(AmStreamConnection::RTP_CONN);
        } else if (local_media.is_dtls_srtp() && AmConfig.enable_srtp) {
            MEDIA_interface &media_if = AmConfig.getMediaIfaceInfo(l_if);
            if (!media_if.srtp->dtls_enable)
                throw string("DTLS is not configured on: ") + media_if.name;
            args.address   = address;
            args.port      = port;
            args.dtls_srtp = (local_media.is_dtls_srtp() && AmConfig.enable_srtp);
            cur_rtp_trans->updateState<AmMediaDtlsState>(args);
            if (cur_rtcp_trans != cur_rtp_trans) {
                args.address = rtcp_address;
                args.port    = rtcp_port;
                cur_rtcp_trans->updateState<AmMediaDtlsState>(args);
            }
            connection_is_muted = cur_rtp_trans->isMute(AmStreamConnection::DTLS_CONN);
        } else if (local_media.transport == TP_UDPTL) {
            args.address = address;
            args.port    = port;
            args.udptl   = true;
            cur_rtp_trans->updateState<AmMediaUdptlState>(args);
            connection_is_muted = cur_rtp_trans->isMute(AmStreamConnection::UDPTL_CONN);
        } else if (local_media.is_dtls_udptl()) {
            MEDIA_interface &media_if = AmConfig.getMediaIfaceInfo(l_if);
            if (!media_if.srtp->dtls_enable)
                throw string("DTLS is not configured on: ") + media_if.name;
            args.address   = address;
            args.port      = port;
            args.dtls_srtp = false;
            cur_rtp_trans->updateState<AmMediaDtlsState>(args);
            connection_is_muted = cur_rtp_trans->isMute(AmStreamConnection::DTLS_CONN);
#ifdef WITH_ZRTP
        } else if (isZrtpEnabled() && AmConfig.enable_srtp && remote_media.zrtp_hash.is_use) {
            args.address = address;
            args.port    = port;
            cur_rtp_trans->updateState<AmMediaZrtpState>(args);
            if (cur_rtcp_trans != cur_rtp_trans) {
                args.address = rtcp_address;
                args.port    = rtcp_port;
                cur_rtcp_trans->updateState<AmMediaZrtpState>(args);
            }
            connection_is_muted = cur_rtp_trans->isMute(AmStreamConnection::ZRTP_CONN);
#endif
        } else {
            args.address = address;
            args.port    = port;
            cur_rtp_trans->updateState<AmMediaRtpState>(args);
            if (cur_rtcp_trans != cur_rtp_trans) {
                args.address = rtcp_address;
                args.port    = rtcp_port;
                cur_rtcp_trans->updateState<AmMediaRtpState>(args);
            }
            connection_is_muted = cur_rtp_trans->isMute(AmStreamConnection::RTP_CONN);
        }
    } catch (string &error) {
        log_demangled_stacktrace(L_ERR);
        CLASS_ERROR("Can't initialize connections. error - %s", error.c_str());
        init_error = error;
        return -1;
    }

    cur_rtp_trans->setPassiveMode(remote_media.dir == SdpMedia::DirActive || remote_media.setup == S_ACTIVE ||
                                  force_passive_mode);
    relay_is_muted = cur_rtp_trans->isMute(AmStreamConnection::RAW_CONN);

    return 0;
}

//
// --- inbound (sink) ---
//

void AmMediaEndpoint::addMember(AmRtpStream *s)
{
    if (raw_mode) {
        CLASS_ERROR("BUG: refusing to add a member to a raw-mode media endpoint");
        return;
    }
    if (std::find(streams.begin(), streams.end(), s) == streams.end())
        streams.push_back(s);
}

void AmMediaEndpoint::removeMember(AmRtpStream *s)
{
    if (streams.size() > 1)
        streams.remove(s);
    else
        CLASS_ERROR("BUG: refusing to remove the last stream from the media endpoint (front() must stay valid)");
}

AmRtpStream *AmMediaEndpoint::getStream(const AmRtpPacket *p) const
{
    if (!p)
        return streams.front(); // default: primary

    // MID header extension (RFC 8843 sec.15): carried in some packets at stream start / SSRC change
    string mid;
    int    ext_id = streams.front()->bundle_mid_ext_id;
    if (ext_id) {
        unsigned char buf[16];
        size_t        len = 0;
        if (p->getHeaderExtension(static_cast<uint8_t>(ext_id), buf, sizeof(buf), len) && len)
            mid.assign(reinterpret_cast<const char *>(buf), len);
    }

    // route to the member: by MID, else by the learned remote SSRC
    for (auto *m : streams) {
        if (!mid.empty()) {
            if (m->bundle_mid == mid)
                return m;
        } else if (m->r_ssrc_i && m->r_ssrc == p->ssrc) {
            return m;
        }
    }
    return streams.front(); // no MID/SSRC match -> default primary
}

AmRtpPacket *AmMediaEndpoint::reuseBufferedPacket()
{
    AmRtpStream   *oldest = nullptr;
    struct timeval best;
    for (auto *s : streams) {
        AmLock l(s->receive_mut);
        if (s->receive_buf.empty())
            continue;
        const struct timeval &t = s->receive_buf.begin()->second->recv_time;
        if (!oldest || timercmp(&t, &best, <)) {
            oldest = s;
            best   = t;
        }
    }
    return oldest ? oldest->reuseBufferedPacket() : nullptr;
}

AmRtpPacket *AmMediaEndpoint::createRtpPacket()
{
    AmRtpPacket *p = mem.newPacket();
    if (!p)
        p = reuseBufferedPacket();
    if (!p) {
        out_of_buffer_errors++;
        CLASS_DBG("out of buffers for RTP packets, dropping");
        mem.debug();
        return 0;
    }
    return p;
}

void AmMediaEndpoint::onErrorRtpTransport(AmStreamConnection::ConnectionError err, const string &error,
                                          AmMediaTransport *t)
{
    struct sockaddr_storage laddr;
    t->getLocalAddr(&laddr);
    if (err == AmStreamConnection::RTP_PARSER_ERROR)
        rtp_parse_errors++;
    else if (err == AmStreamConnection::SRTP_UNPROTECT_ERROR)
        srtp_unprotect_errors++;
    else if (err == AmStreamConnection::STUN_DROPPED_ERROR || err == AmStreamConnection::STUN_VALID_ERROR) {
        CLASS_DBG("%s (src_addr: %s:%i, local_tag: %s)\n", error.c_str(), get_addr_str(&laddr).c_str(),
                  am_get_port(&laddr), session ? session->getLocalTag().c_str() : "no session");
    } else {
        CLASS_ERROR("%s (src_addr: %s:%i, local_tag: %s)\n", error.c_str(), get_addr_str(&laddr).c_str(),
                    am_get_port(&laddr), session ? session->getLocalTag().c_str() : "no session");
    }
}

void AmMediaEndpoint::clearRTPTimeout(struct timeval *recv_time)
{
    for (auto *s : streams)
        s->clearRTPTimeout(recv_time);
}

void AmMediaEndpoint::onRtpPacket(AmRtpPacket *p, AmMediaTransport *t)
{
    clearRTPTimeout(&p->recv_time);
    int parse_res = p->rtp_parse();

    struct sockaddr_storage laddr, raddr;
    p->getAddr(&raddr);
    t->getLocalAddr(&laddr);
    if (parse_res == RTP_PACKET_PARSE_ERROR) {
        string error("error while parsing RTP packet. (src_addr: ");
        error += get_addr_str(&laddr) + ":" + int2str(am_get_port(&laddr)) + ", remote_addr: ";
        error += get_addr_str(&raddr) + ":" + int2str(am_get_port(&raddr)) + ", local_tag: ";
        error += (session ? session->getLocalTag() : string("no session")) + ")";

        onErrorRtpTransport(AmStreamConnection::RTP_PARSER_ERROR, error, t);
        p->release();
    } else if (parse_res == RTP_PACKET_PARSE_OK) {
        AmRtpStream *s = getStream(p); // demux: the packet picks its member (primary for non-bundle / raw)
        s->bufferPacket(p);
        if (cur_rtp_trans != t)
            cur_rtp_trans = t;
    } else {
        CLASS_ERROR("error parsing: rtp packet is RTCP (src_addr: %s:%i, remote_addr: %s:%i, local_tag: %s)\n",
                    get_addr_str(&laddr).c_str(), am_get_port(&laddr), get_addr_str(&raddr).c_str(),
                    am_get_port(&raddr), session ? session->getLocalTag().c_str() : "no session");
        p->release();
        return;
    }
}

void AmMediaEndpoint::onRtcpPacket(AmRtpPacket *p, AmMediaTransport *t)
{
    clearRTPTimeout(&p->recv_time);
    // TODO(C3): per-member RTCP via SDES MID (R14); for now stats go to the primary
    p->rtcp_parse_update_stats(streams.front()->rtp_stats);
    if (cur_rtcp_trans != t && multiplexing)
        cur_rtcp_trans = t;
}

void AmMediaEndpoint::onUdptlPacket(AmRtpPacket *p, AmMediaTransport *)
{
    clearRTPTimeout(&p->recv_time);
    AmRtpStream *s = streams.front(); // UDPTL (T.38) is never bundled
    if (s->relay_enabled && s->relay_raw) {
        // b2b raw-relay: hand off to bufferPacket so relay_stream->relay(p) fires
        s->bufferPacket(p);
        return;
    }
    AmLock l(s->receive_mut);
    if (!s->receive_buf.insert(AmRtpStream::ReceiveBuffer::value_type(p->timestamp, p)).second) {
        p->release();
    }
}

void AmMediaEndpoint::onRawPacket(AmRtpPacket *p, AmMediaTransport *)
{
    AmRtpStream *s = streams.front();
    if (!s->relay_raw) {
        clearRTPTimeout(&p->recv_time);
        p->release();
        return;
    }

    s->bufferPacket(p);
}

void AmMediaEndpoint::onLeavePassiveMode()
{
    symmetric_rtp_enable = false;
}

void AmMediaEndpoint::onRtpEndpointLearned()
{
    if (session)
        session->onRtpEndpointLearned();
}

void AmMediaEndpoint::onTransportEstablished()
{
    if (media_established_fired || !session)
        return;
    auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - media_setup_start)
            .count();
    std::vector<int> indexes;
    indexes.reserve(streams.size());
    for (auto *s : streams)
        indexes.push_back(s->getSdpMediaIndex());
    session->postEvent(new MediaEstablishedEvent(static_cast<unsigned long>(elapsed_ms), std::move(indexes)));
    media_established_fired = true;
}

void AmMediaEndpoint::clearEstablished()
{
    media_established_fired = false;
    media_setup_start       = std::chrono::steady_clock::now();
    iterateTransports([](AmMediaTransport *tr) { tr->clearEstablish(); });
}

void AmMediaEndpoint::resetMediaSetupTimer()
{
    media_setup_start = std::chrono::steady_clock::now();
}

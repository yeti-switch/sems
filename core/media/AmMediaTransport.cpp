#include "AmMediaTransport.h"
#include "media/AmMediaState.h"
#include "AmFaxImage.h"
#include "AmZrtpConnection.h"
#include "AmRtpReceiver.h"
#include "AmRtpPacket.h"
#include "AmSession.h"
#include "AmRtpStream.h"
#include "AmLcConfig.h"
#include "sip/raw_sender.h"

#include <rtp/rtp.h>
#include <sys/ioctl.h>

#define RTCP_PAYLOAD_MIN   72
#define RTCP_PAYLOAD_MAX   76
#define IS_RTCP_PAYLOAD(p) ((p) >= RTCP_PAYLOAD_MIN && (p) <= RTCP_PAYLOAD_MAX)
#define ZRTP_MAGIC_COOKIE  0x5a525450


AmMediaTransport::AmMediaTransport(AmRtpStream *_stream, int _if, int _proto_id, int _type)
    : state(nullptr)
    , conn_factory(this)
    , mode(TRANSPORT_MODE_DEFAULT)
    , setup_mode(S_UNDEFINED)
    , stream(_stream)
    , logger(nullptr)
    , sensor(nullptr)
    , type(_type)
    , l_sd(0)
    , l_sd_ctx(-1)
    , l_port(0)
    , l_if(_if)
    , lproto_id(_proto_id)
    , srtp_enable(false)
    , dtls_enable(false)
    , zrtp_enable(false)
{
    memset(&l_saddr, 0, sizeof(sockaddr_storage));

    recv_iov[0].iov_base = buffer;
    recv_iov[0].iov_len  = RTP_PACKET_BUF_SIZE;

    memset(&recv_msg, 0, sizeof(recv_msg));

    recv_msg.msg_name    = &saddr;
    recv_msg.msg_namelen = sizeof(struct sockaddr_storage);

    recv_msg.msg_iov    = recv_iov;
    recv_msg.msg_iovlen = 1;

    recv_msg.msg_control    = recv_ctl_buf;
    recv_msg.msg_controllen = RTP_PACKET_TIMESTAMP_DATASIZE;

    MEDIA_interface &media_if = AmConfig.getMediaIfaceInfo(_if);
    server_settings           = &media_if.srtp->server_settings;
    client_settings           = &media_if.srtp->client_settings;
    allowed_srtp_profiles     = media_if.srtp->profiles;
    srtp_enable               = media_if.srtp->srtp_enable && AmConfig.enable_srtp;
    dtls_enable               = srtp_enable && media_if.srtp->dtls_enable;
    zrtp_enable               = srtp_enable && media_if.srtp->zrtp_enable;

    stream->getMediaAcl(media_acl);
}

AmMediaTransport::~AmMediaTransport()
{
    DBG("~AmMediaTransport[%p] l_sd = %d", to_void(this), l_sd);
    if (l_sd) {
        if (l_sd_ctx >= 0) {
            if (AmRtpReceiver::haveInstance()) {
                AmRtpReceiver::instance()->removeStream(l_sd, l_sd_ctx);
                l_sd_ctx = -1;
            }
        }
        close(l_sd);
        if (am_get_port(&l_saddr)) {
            AmConfig.media_ifs[l_if].proto_info[lproto_id]->freeRtpAddress(l_saddr);
        }
    }

    if (logger)
        dec_ref(logger);
    if (sensor)
        dec_ref(sensor);
}

void AmMediaTransport::allowStunConnection(const sockaddr_storage *remote_addr, uint32_t priority)
{
    AmLock        l(state_mutex);
    AmMediaState *next_state = 0;
    if (state)
        next_state = state->allowStunConnection(remote_addr, priority);

    if (state.get() != next_state)
        state.reset(next_state);
}

void AmMediaTransport::allowStunPair(const sockaddr_storage *remote_addr)
{
    AmLock        l(state_mutex);
    AmMediaState *next_state = 0;
    if (state)
        next_state = state->allowStunPair(remote_addr);

    if (state.get() != next_state)
        state.reset(next_state);
}

void AmMediaTransport::onSrtpKeysAvailable()
{
    AmLock        l(state_mutex);
    AmMediaState *next_state = 0;
    if (state)
        next_state = state->onSrtpKeysAvailable();

    if (state.get() != next_state)
        state.reset(next_state);
}

void AmMediaTransport::onCloseDtlsSession()
{
    vector<AmStreamConnection::ConnectionType> types{ AmStreamConnection::UDPTL_CONN, AmStreamConnection::RTP_CONN };
    iterateConnections(types, [](AmStreamConnection *conn, bool &stop) {
        DTLSUDPTLConnection *dtls_udptl = dynamic_cast<DTLSUDPTLConnection *>(conn);
        AmSrtpConnection    *srtp       = dynamic_cast<AmSrtpConnection *>(conn);
        if (dtls_udptl)
            dtls_udptl->setDtlsSessionClosed();
        if (srtp)
            srtp->setKeysExpired();
    });
}

const char *AmMediaTransport::state2str()
{
    AmLock l(state_mutex);
    return state2strUnsafe();
}

const char *AmMediaTransport::state2strUnsafe()
{
    static const char *unknown = "UNKNOWN";
    if (state)
        return state->state2str();
    else
        return unknown;
}

void AmMediaTransport::applyOfferSetupMode(Setup offer_mode)
{
    switch (offer_mode) {
    case S_ACTIVE:
    case S_ACTPASS:   setup_mode = S_PASSIVE; break;
    case S_PASSIVE:   setup_mode = S_ACTIVE; break;
    case S_HOLD:      throw AmSession::Exception(488, "hold connections");
    case S_UNDEFINED: throw AmSession::Exception(488, "setup not defined");
    }
}

void AmMediaTransport::setLogger(msg_logger *_logger)
{
    if (logger)
        dec_ref(logger);
    logger = _logger;
    if (logger)
        inc_ref(logger);
}

void AmMediaTransport::setSensor(msg_sensor *_sensor)
{
    if (sensor)
        dec_ref(sensor);
    sensor = _sensor;
    if (sensor)
        inc_ref(sensor);
}

void AmMediaTransport::setRAddr(const string &addr, unsigned short port)
{
    CLASS_DBG("AmMediaTransport::setRAddr(%s, %d)", addr.data(), port);
    AmStreamConnection *raw_conn = nullptr;
    findConnection(AmStreamConnection::RAW_CONN, [&](auto conn) {
        conn->setRAddr(addr, port);
        raw_conn = conn;
    });

    if (raw_conn)
        return;

    CLASS_DBG("create raw connection, state:%s, type:%s, raddr:%s, rport:%d", state2strUnsafe(), type2str(),
              addr.c_str(), port);
    auto new_raw_conn = conn_factory.createRawConnection(addr, port);
    addConnection(new_raw_conn, [&]() { setCurRawConn(new_raw_conn); });
}

void AmMediaTransport::setMode(Mode _mode)
{
    mode = _mode;
}

bool AmMediaTransport::isMute(AmStreamConnection::ConnectionType type)
{
    bool is_mute = false;
    findConnection(type, [&](auto conn) { is_mute = conn->isMute(); });
    return is_mute;
}

string AmMediaTransport::getLocalIP()
{
    return am_inet_ntop(&l_saddr);
}

unsigned short AmMediaTransport::getLocalPort()
{
    return l_port;
}

void AmMediaTransport::getLocalAddr(struct sockaddr_storage *addr)
{
    memcpy(addr, &l_saddr, sizeof(sockaddr_storage));
}

void AmMediaTransport::setLocalAddr(struct sockaddr_storage *addr)
{
    memcpy(&l_saddr, addr, sizeof(sockaddr_storage));
    l_port = am_get_port(addr);
}

AmStreamConnection *AmMediaTransport::getSuitableConnection(bool rtcp)
{
    if (mode == TRANSPORT_MODE_DEFAULT) {
        if (!rtcp) {
            if (getCurRtpConn())
                return getCurRtpConn();
        } else if (getCurRtcpConn())
            return getCurRtcpConn();
    } else if (mode == TRANSPORT_MODE_FAX || mode == TRANSPORT_MODE_DTLS_FAX) {
        if (getCurUdptlConn())
            return getCurUdptlConn();
    }
    return getCurRawConn();
}

IceContext *AmMediaTransport::getIceContext()
{
    return stream->getIceContext(type);
}

string AmMediaTransport::getRHost(bool rtcp)
{
    auto c = getSuitableConnection(rtcp);
    if (c)
        return c->getRHost();
    return "";
}

int AmMediaTransport::getRPort(bool rtcp)
{
    auto c = getSuitableConnection(rtcp);
    if (c)
        return c->getRPort();
    return 0;
}

void AmMediaTransport::getRAddr(bool rtcp, sockaddr_storage *addr)
{
    auto c = getSuitableConnection(rtcp);
    if (c)
        c->getRAddr(addr);
}

void AmMediaTransport::getRAddr(sockaddr_storage *addr)
{
    if (getCurRawConn())
        getCurRawConn()->getRAddr(addr);
}

int AmMediaTransport::hasLocalSocket()
{
    return l_sd;
}

int AmMediaTransport::getLocalSocket(bool reinit)
{
    CLASS_DBG("> getLocalSocket(%d)", reinit);

    if (l_sd) {
        if (!reinit) {
            CLASS_DBG("< return existent l_sd:%d", l_sd);
            return l_sd;
        } else {
            if (am_get_port(&l_saddr))
                AmConfig.media_ifs[l_if].proto_info[lproto_id]->freeRtpAddress(l_saddr);
            close(l_sd);
            l_sd = 0;
        }
    }

    int sd = 0;
    if ((sd = socket(AmConfig.media_ifs[l_if].proto_info[lproto_id]->type_ip == AT_V4 ? AF_INET : AF_INET6, SOCK_DGRAM,
                     0)) == -1)
    {
        CLASS_ERROR("< %s", strerror(errno));
        throw string("while creating new socket.");
    }
    SOCKET_LOG("[%p] socket(l_saddr.ss_family(%d),SOCK_DGRAM,0) = %d", to_void(this), l_saddr.ss_family, sd);

    int true_opt = 1;
    if (ioctl(sd, FIONBIO, &true_opt) == -1) {
        CLASS_ERROR("< %s", strerror(errno));
        close(sd);
        throw string("while setting RTP socket non blocking.");
    }

    if (setsockopt(sd, SOL_SOCKET, SO_TIMESTAMP, static_cast<void *>(&true_opt), sizeof(true_opt)) < 0) {
        CLASS_ERROR("< %s", strerror(errno));
        close(sd);
        throw string("while setting RTP socket SO_TIMESTAMP opt");
    }

    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, static_cast<void *>(&true_opt), sizeof(true_opt)) == -1) {
        ERROR("%s", strerror(errno));
        close(sd);
        sd = 0;
        throw string("while setting local address reusable.");
    }

    int tos = AmConfig.getMediaProtoInfo(l_if, lproto_id).tos_byte;
    if (tos && setsockopt(sd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == -1) {
        CLASS_WARN("failed to set IP_TOS for descriptors %d", sd);
    }

    l_sd = sd;

    CLASS_DBG("< return newly created l_sd:%d", l_sd);
    return l_sd;
}

void AmMediaTransport::getSdpOffer(SdpMedia &offer)
{
    CLASS_DBG("AmMediaTransport::getSdpOffer");

    // set offer type
    switch (offer.transport) {
    case TP_UDPTL:
    case TP_UDPTLSUDPTL: offer.type = MT_IMAGE; break;
    default:             offer.type = MT_AUDIO;
    }

    // process failovers
    switch (offer.transport) {
    case TP_RTPSAVP:
    case TP_RTPSAVPF:
        if (!srtp_enable) {
            CLASS_WARN("SRTP is disabled on related interface (%s). failover to RTPAVP profile",
                       AmConfig.getMediaIfaceInfo(l_if).name.c_str());
            offer.transport = TP_RTPAVP;
        }
        break;
    case TP_UDPTLSRTPSAVP:
    case TP_UDPTLSRTPSAVPF:
        if (!dtls_enable) {
            CLASS_WARN("DTLS is disabled on related interface (%s). failover to RTPAVP profile",
                       AmConfig.getMediaIfaceInfo(l_if).name.c_str());
            offer.transport = TP_RTPAVP;
        }
        break;
    default: break;
    }

    // init related options
    switch (offer.transport) {
    case TP_RTPSAVP:
    case TP_RTPSAVPF:
        if (local_crypto.empty()) {
            int i = 0;
            for (auto profile : allowed_srtp_profiles) {
                SdpCrypto crypto;
                crypto.profile  = profile;
                std::string key = AmSrtpConnection::gen_base64_key(static_cast<srtp_profile_t>(crypto.profile));
                if (key.empty()) {
                    continue;
                }
                crypto.tag = ++i;
                local_crypto.push_back(crypto);
                local_crypto.back().keys.push_back(SdpKeyInfo(key));
            }
        }
        offer.crypto = local_crypto;
        break;
    case TP_UDPTLSRTPSAVP:
    case TP_UDPTLSRTPSAVPF:
    {
        if (local_dtls_fingerprint.hash.empty()) {
            srtp_fingerprint_p fp        = DtlsContext::gen_fingerprint(server_settings);
            local_dtls_fingerprint.hash  = fp.hash;
            local_dtls_fingerprint.value = fp.value;
        }
        offer.fingerprint = local_dtls_fingerprint;

        if (setup_mode == S_UNDEFINED)
            setup_mode = S_ACTPASS;
        offer.setup = setup_mode;
    } break;
    case TP_UDPTL:
    {
        t38_options_t options;
        options.getT38DefaultOptions();
        options.getAttributes(offer);
        offer.payloads.clear();
        offer.fmt = T38_FMT;
    } break;
    case TP_UDPTLSUDPTL:
    {
        if (local_dtls_fingerprint.hash.empty()) {
            srtp_fingerprint_p fp        = DtlsContext::gen_fingerprint(server_settings);
            local_dtls_fingerprint.hash  = fp.hash;
            local_dtls_fingerprint.value = fp.value;
        }
        offer.fingerprint = local_dtls_fingerprint;

        if (setup_mode == S_UNDEFINED)
            setup_mode = S_ACTPASS;
        offer.setup = setup_mode;

        t38_options_t options;
        options.getT38DefaultOptions();
        options.getAttributes(offer);
        offer.payloads.clear();
        offer.fmt = T38_FMT;
    } break;
    default:
#ifdef WITH_ZRTP
        if (stream->isZrtpEnabled() && zrtp_enable) {
            offer.zrtp_hash.hash = stream->getZrtpContext()->getLocalHash(stream->get_ssrc());
            if (!offer.zrtp_hash.hash.empty())
                offer.zrtp_hash.is_use = true;
        }
#endif /*WITH_ZRTP*/
        break;
    }
}

void AmMediaTransport::getSdpAnswer(const SdpMedia &offer, SdpMedia &answer)
{
    CLASS_DBG("AmMediaTransport::getSdpAnswer");

    int transport = offer.transport;
    if (transport != TP_UDPTL && transport != TP_UDPTLSUDPTL)
        answer.type = MT_AUDIO;
    else
        answer.type = MT_IMAGE;

    if ((offer.is_simple_srtp() && !srtp_enable) || (offer.is_dtls_srtp() && !dtls_enable)) {
        std::string error(offer.is_simple_srtp() ? "SRTP" : "DTLS");
        error += " transport is not supported";
        CLASS_ERROR("[%s] %s on interface(%d/%s)", stream ? stream->getSessionLocalTag() : "null", error.c_str(), l_if,
                    AmConfig.media_ifs[l_if].proto_info[lproto_id]->transportToStr().c_str());
        throw AmSession::Exception(488, error);
    } else if (transport == TP_RTPSAVP || transport == TP_RTPSAVPF) {
        if (offer.crypto.empty()) {
            throw AmSession::Exception(488, "absent crypto attribute");
        }
        // TODO: check intersection with SDP offer if local_crypto is not empty
        if (local_crypto.empty()) {
            for (const auto &allowed_profile : allowed_srtp_profiles) {
                for (const auto &offer_crypto : offer.crypto) {
                    if (allowed_profile == offer_crypto.profile) {
                        local_crypto.emplace_back(offer_crypto);
                        auto &c = local_crypto.back();
                        c.keys.clear();
                        c.keys.emplace_back(
                            SdpKeyInfo(AmSrtpConnection::gen_base64_key(static_cast<srtp_profile_t>(c.profile))));
                        break;
                    }
                }
                if (!local_crypto.empty())
                    break;
            }
        }
        if (local_crypto.empty()) {
            throw AmSession::Exception(488, "no compatible srtp profile");
        }
        answer.crypto = local_crypto;
    } else if (transport == TP_UDPTLSRTPSAVP || transport == TP_UDPTLSRTPSAVPF) {
        applyOfferSetupMode(offer.setup);
        dtls_settings *settings = (setup_mode == S_PASSIVE) ? static_cast<dtls_settings *>(server_settings)
                                                            : static_cast<dtls_settings *>(client_settings);
        if (local_dtls_fingerprint.hash.empty()) {
            srtp_fingerprint_p fp        = DtlsContext::gen_fingerprint(settings);
            local_dtls_fingerprint.hash  = fp.hash;
            local_dtls_fingerprint.value = fp.value;
        }

        answer.fingerprint = local_dtls_fingerprint;
        answer.setup       = setup_mode;
    } else if (transport == TP_UDPTL) {
        t38_options_t options;
        options.negotiateT38Options(offer.attributes);
        options.getAttributes(answer);
        answer.payloads.clear();
        answer.fmt = T38_FMT;
    } else if (transport == TP_UDPTLSUDPTL) {
        applyOfferSetupMode(offer.setup);
        dtls_settings *settings = (setup_mode == S_PASSIVE) ? static_cast<dtls_settings *>(server_settings)
                                                            : static_cast<dtls_settings *>(client_settings);
        if (local_dtls_fingerprint.hash.empty()) {
            srtp_fingerprint_p fp        = DtlsContext::gen_fingerprint(settings);
            local_dtls_fingerprint.hash  = fp.hash;
            local_dtls_fingerprint.value = fp.value;
        }
        answer.fingerprint = local_dtls_fingerprint;
        answer.setup       = setup_mode;

        t38_options_t options;
        options.negotiateT38Options(offer.attributes);
        options.getAttributes(answer);
        answer.payloads.clear();
        answer.fmt = T38_FMT;
#ifdef WITH_ZRTP
    } else if (stream->isZrtpEnabled() && zrtp_enable && offer.zrtp_hash.is_use) {
        answer.zrtp_hash.hash = stream->getZrtpContext()->getLocalHash(stream->get_ssrc());
        if (!answer.zrtp_hash.hash.empty())
            answer.zrtp_hash.is_use = true;
#endif /*WITH_ZRTP*/
    }
}

void AmMediaTransport::prepareIceCandidate(SdpIceCandidate &candidate)
{
    candidate.conn.network  = NT_IN;
    candidate.comp_id       = getComponentId();
    candidate.conn.addrType = (l_saddr.ss_family == AF_INET) ? AT_V4 : AT_V6;
    candidate.conn.address  = am_inet_ntop(&l_saddr);
    candidate.conn.port     = l_port;
}

sockaddr_storage *AmMediaTransport::getAllowedIceAddr()
{
    return getIceContext()->getAllowedIceAddr(getLocalAddrFamily());
}

void AmMediaTransport::setIcePriority(unsigned int priority)
{
    conn_factory.ice_cred.lpriority = priority;
}

void AmMediaTransport::getInfo(AmArg &ret)
{
    if (mode == TRANSPORT_MODE_FAX)
        ret["mode"] = "fax";
    else if (mode == TRANSPORT_MODE_DTLS_FAX)
        ret["mode"] = "dtls_fax";
    else if (mode == TRANSPORT_MODE_RAW)
        ret["mode"] = "raw";
    else if (mode == TRANSPORT_MODE_DEFAULT)
        ret["mode"] = "default";

    if (type == FAX_TRANSPORT)
        ret["type"] = "fax";
    if (type == RTP_TRANSPORT)
        ret["type"] = "rtp";
    if (type == RTCP_TRANSPORT)
        ret["type"] = "rtcp";

    ret["state"] = state2str();

    AmArg &conns = ret["connections"];
    iterateConnections([&](auto conn, bool &stop) {
        AmArg arg_conn;
        conn->getInfo(arg_conn);
        conns.push(arg_conn);
    });
}

void AmMediaTransport::dtls_alert(const Botan::TLS::Alert &alert)
{
    if (alert.type() == Botan::TLS::Alert::CloseNotify) {
        stream->onCloseDtlsSession(getTransportType());
        return;
    }

    CLASS_ERROR("DTLS local_tag:%s, alert:%s", stream->getSessionLocalTag(), alert.type_string().c_str());
}

void AmMediaTransport::onRtpPacket(AmRtpPacket *packet, AmStreamConnection *conn)
{
    if (!getCurRtpConn())
        setCurRtpConn(conn);
    stream->onRtpPacket(packet, this);
}

void AmMediaTransport::onRtcpPacket(AmRtpPacket *packet, AmStreamConnection *conn)
{
    if (!getCurRtcpConn())
        setCurRtcpConn(conn);
    stream->onRtcpPacket(packet, this);
}

void AmMediaTransport::onRawPacket(AmRtpPacket *packet, AmStreamConnection *conn)
{
    if (mode == TRANSPORT_MODE_DEFAULT) {
        onPacket(packet->getBuffer(), packet->getBufferSize(), packet->saddr, packet->recv_time);
        stream->freeRtpPacket(packet);
    } else if (mode == TRANSPORT_MODE_FAX || mode == TRANSPORT_MODE_DTLS_FAX) {
        setCurUdptlConn(conn);
        stream->onUdptlPacket(packet, this);
    } else {
        setCurRawConn(conn);
        stream->onRawPacket(packet, this);
    }
}

void AmMediaTransport::stopReceiving()
{
    AmLock l1(stream_mut);
    CLASS_DBG("stopReceiving() l_sd:%d, state:%s, type:%s", l_sd, state2str(), type2str());
    if (hasLocalSocket() && state) {
        CLASS_DBG("remove stream %p %s transport from RTP receiver", to_void(stream), type2str());
        AmRtpReceiver::instance()->removeStream(getLocalSocket(), l_sd_ctx);
        l_sd_ctx = -1;
    }
}

void AmMediaTransport::resumeReceiving()
{
    AmLock l1(stream_mut);
    CLASS_DBG("resumeReceiving() l_sd:%d, state:%s, type:%s", l_sd, state2str(), type2str());
    if (hasLocalSocket() && state) {
        CLASS_DBG("add/resume stream %p %s transport into RTP receiver", to_void(stream), type2str());
        l_sd_ctx = AmRtpReceiver::instance()->addStream(l_sd, this, l_sd_ctx);
        if (l_sd_ctx < 0) {
            CLASS_DBG("error on add/resuming stream. l_sd_ctx = %d", l_sd_ctx);
        }
    }
}

void AmMediaTransport::setPassiveMode(bool p)
{
    iterateConnections([&](auto conn, bool &stop) { conn->setPassiveMode(p); });
}

void AmMediaTransport::log_rcvd_packet(const char *buffer, int len, struct sockaddr_storage &recv_addr,
                                       AmStreamConnection::ConnectionType type)
{
    static const cstring empty;
    if (logger)
        logger->log(buffer, len, &recv_addr, &l_saddr, empty);
    if (sensor)
        sensor->feed(buffer, static_cast<int>(b_size), &saddr, &l_saddr, streamConnType2sensorPackType(type));
}

void AmMediaTransport::log_sent_packet(const char *buffer, int len, struct sockaddr_storage &send_addr,
                                       AmStreamConnection::ConnectionType type)
{
    static const cstring empty;
    if (logger)
        logger->log(buffer, len, &l_saddr, &send_addr, empty);
    if (sensor)
        sensor->feed(buffer, static_cast<int>(b_size), &l_saddr, &send_addr, streamConnType2sensorPackType(type));
}

ssize_t AmMediaTransport::send(AmRtpPacket *packet, AmStreamConnection::ConnectionType type)
{
    // CLASS_DBG("send(%p,%d)", packet, type);
    AmStreamConnection *cur_stream = nullptr;
    if (type == AmStreamConnection::RTP_CONN) {
        cur_stream = getCurRtpConn();
    } else if (type == AmStreamConnection::RTCP_CONN) {
        cur_stream = getCurRtcpConn();
    } else if (type == AmStreamConnection::RAW_CONN) {
        cur_stream = getCurRawConn();
    } else if (type == AmStreamConnection::UDPTL_CONN) {
        cur_stream = getCurUdptlConn();
    }

    ssize_t ret = 0;
    if (cur_stream) {
        ReferenceGuard<AmStreamConnection> rg(cur_stream);
        if (!cur_stream->isMute())
            ret = cur_stream->send(packet);
    } else {
        findConnection([&](auto conn) { return conn->isUseConnection(type) && !conn->isMute(); },
                       [&](auto conn) { ret = conn->send(packet); });
    }

    if (ret > 0) {
        stream->update_sender_stats(*packet);
    }

    return ret;
}

ssize_t AmMediaTransport::send(sockaddr_storage *raddr, unsigned char *buf, int size,
                               AmStreamConnection::ConnectionType type)
{
    /*CLASS_DBG("send(%s:%hu,%p,%d,%d)",
              get_addr_str(raddr).data(), am_get_port(raddr),
              buf,size,type);*/
    log_sent_packet(reinterpret_cast<const char *>(buf), size, *raddr, type);

    MEDIA_info *iface = AmConfig.media_ifs[static_cast<size_t>(l_if)].proto_info[static_cast<size_t>(lproto_id)];

    if (iface->net_if_idx) {
        if (iface->sig_sock_opts & trsp_socket::use_raw_sockets) {
            return raw_sender::send(reinterpret_cast<char *>(buf), static_cast<unsigned int>(size),
                                    static_cast<int>(iface->net_if_idx), &l_saddr, raddr, iface->tos_byte);
        }
        // TODO: process case with AmConfig.force_outbound_if properly for rtcp
        if (AmConfig.force_outbound_if) {
            return sendmsg(buf, size);
        }
    }

    ssize_t err = ::sendto(l_sd, buf, static_cast<size_t>(size), 0, reinterpret_cast<const struct sockaddr *>(raddr),
                           SA_len(raddr));

    if (err == -1) {
        if (AmConfig.rtp_send_errors_log_level >= 0) {
            _LOG(AmConfig.rtp_send_errors_log_level, "sendto(%d,%p,%d,0,%p,%ld): errno: %d, raddr:'%s', type: %d", l_sd,
                 static_cast<void *>(buf), size, static_cast<void *>(raddr), SA_len(raddr), errno,
                 get_addr_str(raddr).data(), type);
            // log_stacktrace(L_DBG);
        }
        return -1;
    }
    return err;
}

int AmMediaTransport::sendmsg(unsigned char *buf, int size)
{
    MEDIA_info  &iface      = AmConfig.getMediaProtoInfo(l_if, lproto_id);
    unsigned int sys_if_idx = iface.net_if_idx;

    struct msghdr   hdr;
    struct cmsghdr *cmsg;

    union {
        char cmsg4_buf[CMSG_SPACE(sizeof(struct in_pktinfo))];
        char cmsg6_buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    } cmsg_buf;

    struct iovec msg_iov[1];
    msg_iov[0].iov_base = to_void(buf);
    msg_iov[0].iov_len  = static_cast<size_t>(size);

    bzero(&hdr, sizeof(hdr));
    hdr.msg_name    = to_void(&l_saddr);
    hdr.msg_namelen = SA_len(&l_saddr);
    hdr.msg_iov     = msg_iov;
    hdr.msg_iovlen  = 1;

    bzero(&cmsg_buf, sizeof(cmsg_buf));
    hdr.msg_control    = &cmsg_buf;
    hdr.msg_controllen = sizeof(cmsg_buf);

    cmsg = CMSG_FIRSTHDR(&hdr);
    if (l_saddr.ss_family == AF_INET) {
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type  = IP_PKTINFO;
        cmsg->cmsg_len   = CMSG_LEN(sizeof(struct in_pktinfo));

        struct in_pktinfo *pktinfo = reinterpret_cast<struct in_pktinfo *>(CMSG_DATA(cmsg));
        pktinfo->ipi_ifindex       = static_cast<int>(sys_if_idx);
    } else if (l_saddr.ss_family == AF_INET6) {
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type  = IPV6_PKTINFO;
        cmsg->cmsg_len   = CMSG_LEN(sizeof(struct in6_pktinfo));

        struct in6_pktinfo *pktinfo = reinterpret_cast<struct in6_pktinfo *>(CMSG_DATA(cmsg));
        pktinfo->ipi6_ifindex       = sys_if_idx;
    }

    hdr.msg_controllen = cmsg->cmsg_len;

    // bytes_sent = ;
    if (::sendmsg(l_sd, &hdr, 0) < 0) {
        ERROR("sendto: %s", strerror(errno));
        return -1;
    }

    return 0;
}

ssize_t AmMediaTransport::recv(int sd)
{
    cmsghdr *cmsgptr;
    ssize_t  ret = recvmsg(sd, &recv_msg, 0);

    for (cmsgptr = CMSG_FIRSTHDR(&recv_msg); cmsgptr != nullptr; cmsgptr = CMSG_NXTHDR(&recv_msg, cmsgptr)) {
        if (cmsgptr->cmsg_level == SOL_SOCKET && cmsgptr->cmsg_type == SO_TIMESTAMP) {
            memcpy(&recv_time, CMSG_DATA(cmsgptr), sizeof(struct timeval));
        }
    }

    if (ret > 0) {
        if (ret > 4096)
            return -1;
        b_size = static_cast<unsigned int>(ret);
    }

    return ret;
}

void AmMediaTransport::recvPacket(int fd)
{
    if (recv(fd) > 0) {
        trsp_acl::action_t action = media_acl.check(saddr);
        if (action == trsp_acl::Allow)
            onPacket(buffer, b_size, saddr, recv_time);
        else {
            stream->inc_drop_pack();
            AmRtpReceiver::instance()->inc_drop_packets();
        }
    }
}

void AmMediaTransport::onPacket(unsigned char *buf, unsigned int size, sockaddr_storage &addr, struct timeval recvtime)
{
    stream->updateRcvdBytes(size);
    AmStreamConnection::ConnectionType ctype;
    if (mode == TRANSPORT_MODE_DEFAULT) {
        ctype = GetConnectionType(buf, size);
        if (ctype == AmStreamConnection::UNKNOWN_CONN) {
            CLASS_DBG("Unknown packet type from %s:%d, ignore it", am_inet_ntop(&addr).c_str(), am_get_port(&addr));
            return;
        }
    } else if (mode == TRANSPORT_MODE_FAX) {
        ctype = AmStreamConnection::UDPTL_CONN;
    } else if (mode == TRANSPORT_MODE_DTLS_FAX) {
        ctype = AmStreamConnection::DTLS_CONN;
    } else {
        ctype = AmStreamConnection::RAW_CONN;
    }

    log_rcvd_packet(reinterpret_cast<const char *>(buf), static_cast<int>(size), addr, ctype);

    AmStreamConnection *s_conn = nullptr;

    findConnection([&](auto conn) { return conn->isUseConnection(ctype) && conn->isAddrConnection(&addr); },
                   [&](auto conn) { s_conn = conn; });

    if (!s_conn && ctype != AmStreamConnection::STUN_CONN)
        findConnection([&](auto conn) { return conn->isUseConnection(ctype); }, [&](auto conn) { s_conn = conn; });

    if (!s_conn) {
        if (ctype == AmStreamConnection::STUN_CONN && stream->isIceStream()) {
            const uint32_t lpriority = (ICT_HOST << 24) | ((rand() & 0xffff) << 8) | (256 - type);
            const string   addr_str  = am_inet_ntop(&addr);
            const int      port      = am_get_port(&addr);

            CLASS_DBG("add stun connection, state:%s, type:%s, addr:%s, port:%d", state2str(), type2str(),
                      addr_str.c_str(), port);

            s_conn = conn_factory.createStunConnection(addr_str, port, lpriority);
            addConnection(s_conn);
        } else
            return;
    }

    ReferenceGuard<AmStreamConnection> rg(s_conn);
    s_conn->process_packet(buf, size, &addr, recvtime);
}

int AmMediaTransport::getSrtpCredentialsBySdp(const SdpMedia &local_media, const SdpMedia &remote_media, string &l_key,
                                              srtp_master_keys &r_keys)
{
    CryptoProfile cprofile = CP_NONE;
    if (local_media.crypto.size() == 1) {
        cprofile = local_media.crypto[0].profile;
    } else if (remote_media.crypto.size() == 1) {
        cprofile = remote_media.crypto[0].profile;
    } else if (local_media.crypto.empty()) {
        CLASS_ERROR("local secure audio stream without encryption details");
        return -1;
    } else if (remote_media.crypto.empty()) {
        CLASS_ERROR("remote secure audio stream without encryption details");
        return -1;
    } else {
        CLASS_WARN("secure audio stream with some encryption details, use local first");
        cprofile = local_media.crypto[0].profile;
    }

    unsigned char local_key[SRTP_KEY_SIZE], remote_key[SRTP_KEY_SIZE];
    unsigned int  local_key_size = SRTP_KEY_SIZE, remote_key_size = SRTP_KEY_SIZE;

    // get local key
    auto local_crypto_profile_it = std::find_if(local_media.crypto.begin(), local_media.crypto.end(),
                                                [cprofile](const SdpCrypto &s) { return s.profile == cprofile; });
    if (local_crypto_profile_it == local_media.crypto.end()) {
        CLASS_ERROR("no chosen profile %s in local media crypto attributes", SdpCrypto::profile2str(cprofile).data());
        return -1;
    }
    if (local_crypto_profile_it->keys.empty()) {
        CLASS_ERROR("local secure audio stream without master key");
        return -1;
    }

    // reduce local_crypto vector to the chosen profile (to generate correct answer for reINVITES)
    local_crypto.insert(local_crypto.begin(), *local_crypto_profile_it);
    local_crypto.resize(1);

    AmSrtpConnection::base64_key(local_crypto_profile_it->keys[0].key, local_key, local_key_size);
    l_key.assign(reinterpret_cast<char *>(local_key), local_key_size);

    // get remote key
    auto remote_crypto_profile_it = std::find_if(remote_media.crypto.begin(), remote_media.crypto.end(),
                                                 [cprofile](const SdpCrypto &s) { return s.profile == cprofile; });
    if (remote_crypto_profile_it == remote_media.crypto.end()) {
        CLASS_ERROR("no chosen profile %s in remote media crypto attributes", SdpCrypto::profile2str(cprofile).data());
        return -1;
    }
    if (remote_crypto_profile_it->keys.empty()) {
        CLASS_ERROR("remote secure audio stream without master key");
        return -1;
    }
    for (auto &key : remote_crypto_profile_it->keys) {
        string rkey;
        AmSrtpConnection::base64_key(key.key, remote_key, remote_key_size);
        rkey.assign(reinterpret_cast<char *>(remote_key), remote_key_size);
        r_keys.add(rkey, key.mki.id, key.mki.len);
        if (!key.mki.len)
            break;
    }

    return cprofile;
}

AmStreamConnection::ConnectionType AmMediaTransport::GetConnectionType(unsigned char *buf, unsigned int size)
{
    if (isStunMessage(buf, size))
        return AmStreamConnection::STUN_CONN;
    if (isDTLSMessage(buf, size))
        return AmStreamConnection::DTLS_CONN;
    if (isRTCPMessage(buf, size))
        return AmStreamConnection::RTCP_CONN;
    if (isRTPMessage(buf, size))
        return AmStreamConnection::RTP_CONN;
    if (isZRTPMessage(buf, size))
        return AmStreamConnection::ZRTP_CONN;

    return AmStreamConnection::UNKNOWN_CONN;
}

bool AmMediaTransport::isStunMessage(unsigned char *buf, unsigned int size)
{
    if (size < sizeof(unsigned short)) {
        return false;
    }

    // RFC 5764 5.1.2. Reception
    return *buf < 2;
}

bool AmMediaTransport::isDTLSMessage(unsigned char *buf, unsigned int size)
{
    if (!size) {
        return false;
    }

    // RFC 5764 5.1.2. Reception
    return *buf < 64 && *buf > 19;
}

bool AmMediaTransport::isRTCPMessage(unsigned char *buf, unsigned int size)
{
    if (size < sizeof(rtp_hdr_t)) {
        return false;
    }

    // RFC 5764 5.1.2. Reception
    if (*buf > 192 || *buf < 127)
        return false;

    rtp_hdr_t *rtp = reinterpret_cast<rtp_hdr_t *>(buf);
    if (IS_RTCP_PAYLOAD(rtp->pt)) {
        return true;
    }
    return false;
}

bool AmMediaTransport::isRTPMessage(unsigned char *buf, unsigned int size)
{
    if (size < sizeof(rtp_hdr_t)) {
        return false;
    }

    // RFC 5764 5.1.2. Reception
    if (*buf > 192 || *buf < 127)
        return false;

    // RFC 5764 5.1.2. Reception
    rtp_hdr_t *rtp = reinterpret_cast<rtp_hdr_t *>(buf);
    if (!IS_RTCP_PAYLOAD(rtp->pt)) {
        return true;
    }
    return false;
}

bool AmMediaTransport::isZRTPMessage(unsigned char *buf, unsigned int size)
{
    if (size < sizeof(rtp_hdr_t)) {
        return false;
    }

    // RFC 6189 5.0 ZRTP packet format
    if (*buf != 16 && *(((int *)buf) + 1) != ZRTP_MAGIC_COOKIE)
        return false;

    return true;
}

msg_sensor::packet_type_t AmMediaTransport::streamConnType2sensorPackType(AmStreamConnection::ConnectionType type)
{
    switch (type) {
    case AmStreamConnection::RTP_CONN:  return msg_sensor::PTYPE_RTP;
    case AmStreamConnection::RTCP_CONN: return msg_sensor::PTYPE_RTCP;
    case AmStreamConnection::DTLS_CONN: return msg_sensor::PTYPE_DTLS;
    case AmStreamConnection::STUN_CONN: return msg_sensor::PTYPE_STUN;
    default:                            return msg_sensor::PTYPE_UNKNOWN;
    }
}

const char *AmMediaTransport::type2str()
{
    static const char *rtp     = "RTP";
    static const char *rtcp    = "RTCP";
    static const char *fax     = "FAX";
    static const char *raw     = "RAW";
    static const char *unknown = "UNKNOWN";

    switch (type) {
    case RTP_TRANSPORT:  return rtp;
    case RTCP_TRANSPORT: return rtcp;
    case FAX_TRANSPORT:  return fax;
    case RAW_TRANSPORT:  return raw;
    default:             return unknown;
    }
}

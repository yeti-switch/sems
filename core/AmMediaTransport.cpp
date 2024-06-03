#include "AmMediaTransport.h"
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

#define RTCP_PAYLOAD_MIN 72
#define RTCP_PAYLOAD_MAX 76
#define IS_RTCP_PAYLOAD(p) ((p) >= RTCP_PAYLOAD_MIN && (p) <= RTCP_PAYLOAD_MAX)
#define ZRTP_MAGIC_COOKIE   0x5a525450

inline const char *transport_type2str(int type)
{
    static const char *rtp = "RTP";
    static const char *rtcp = "RTCP";
    static const char *fax = "FAX";
    static const char *raw = "RAW";
    switch(type) {
    case RTP_TRANSPORT: return rtp;
    case RTCP_TRANSPORT: return rtcp;
    case FAX_TRANSPORT: return fax;
    default: return raw; }
}

AmMediaTransport::AmMediaTransport(AmRtpStream* _stream, int _if, int _proto_id, int type)
  : state(TRANSPORT_STATE_NONE),
    mode(TRANSPORT_MODE_DEFAULT),
    stream(_stream),
    cur_rtp_conn(nullptr),
    cur_rtcp_conn(nullptr),
    cur_udptl_conn(nullptr),
    cur_raw_conn(nullptr),
    logger(nullptr),
    sensor(nullptr),
    type(type),
    l_sd(0),
    l_sd_ctx(-1),
    l_port(0),
    l_if(_if),
    lproto_id(_proto_id),
    srtp_enable(false),
    dtls_enable(false),
    zrtp_enable(false)
{
    srtp_cred.srtp_profile = srtp_profile_reserved;
    memset(&l_saddr, 0, sizeof(sockaddr_storage));

    recv_iov[0].iov_base = buffer;
    recv_iov[0].iov_len  = RTP_PACKET_BUF_SIZE;

    memset(&recv_msg,0,sizeof(recv_msg));

    recv_msg.msg_name       = &saddr;
    recv_msg.msg_namelen    = sizeof(struct sockaddr_storage);

    recv_msg.msg_iov        = recv_iov;
    recv_msg.msg_iovlen     = 1;

    recv_msg.msg_control    = recv_ctl_buf;
    recv_msg.msg_controllen = RTP_PACKET_TIMESTAMP_DATASIZE;

    MEDIA_interface& media_if = AmConfig.getMediaIfaceInfo(_if);
    server_settings = &media_if.srtp->server_settings;
    client_settings = &media_if.srtp->client_settings;
    allowed_srtp_profiles = media_if.srtp->profiles;
    srtp_enable = media_if.srtp->srtp_enable && AmConfig.enable_srtp;
    dtls_enable = srtp_enable && media_if.srtp->dtls_enable;
    zrtp_enable = srtp_enable && media_if.srtp->zrtp_enable;

    stream->getMediaAcl(media_acl);
}

AmMediaTransport::~AmMediaTransport()
{
    DBG("~AmMediaTransport[%p] l_sd = %d",to_void(this), l_sd);
    if(l_sd) {
        if(l_sd_ctx >= 0) {
            if (AmRtpReceiver::haveInstance()) {
                AmRtpReceiver::instance()->removeStream(l_sd,l_sd_ctx);
                l_sd_ctx = -1;
            }
        }
        close(l_sd);
        if(am_get_port(&l_saddr)) {
            AmConfig.media_ifs[l_if].proto_info[lproto_id]->freeRtpAddress(l_saddr);
        }
    }

    for(auto conn : connections) {
        delete conn;
    }

    connections.clear();

    if (logger) dec_ref(logger);
    if (sensor) dec_ref(sensor);
}

void AmMediaTransport::setLogger(msg_logger* _logger)
{
    if (logger) dec_ref(logger);
        logger = _logger;
    if (logger) inc_ref(logger);
}

void AmMediaTransport::setSensor(msg_sensor *_sensor)
{
    if(sensor) dec_ref(sensor);
        sensor = _sensor;
    if(sensor) inc_ref(sensor);
}

void AmMediaTransport::setRAddr(const string& addr, unsigned short port)
{
    CLASS_DBG("AmMediaTransport::setRAddr(%s, %d)", addr.data(), port);
    AmLock l(connections_mut);
    for(auto conn : connections) {
        if(conn->getConnType() == AmStreamConnection::RAW_CONN) {
            conn->setRAddr(addr, port);
            return;
        }
    }

    connections.push_back(new AmRawConnection(this, addr, port));
    cur_raw_conn = connections.back();
}

void AmMediaTransport::setMode(Mode _mode)
{
    mode = _mode;
}

bool AmMediaTransport::isMute(int type)
{
    bool ret = false;
    AmLock l(connections_mut);
    for(auto conn : connections) {
        if(conn->getConnType() == type/*AmStreamConnection::RAW_CONN*/) {
            ret = conn->isMute();
            break;
        }
    }

    return ret;
}

string AmMediaTransport::getLocalIP()
{
    return am_inet_ntop(&l_saddr);
}

unsigned short AmMediaTransport::getLocalPort()
{
    return l_port;
}

void AmMediaTransport::getLocalAddr(struct sockaddr_storage* addr)
{
    memcpy(addr, &l_saddr, sizeof(sockaddr_storage));
}

void AmMediaTransport::setLocalAddr(struct sockaddr_storage* addr)
{
    memcpy(&l_saddr, addr, sizeof(sockaddr_storage));
    l_port = am_get_port(addr);
}

AmStreamConnection* AmMediaTransport::getSuitableConnection(bool rtcp)
{
    if(mode == TRANSPORT_MODE_DEFAULT) {
        if(!rtcp) {
            if(cur_rtp_conn) return cur_rtp_conn;
        } else if(cur_rtcp_conn)
            return cur_rtcp_conn;
    } else if(mode == TRANSPORT_MODE_FAX ||
              mode == TRANSPORT_MODE_DTLS_FAX) {
        if(cur_udptl_conn) return cur_udptl_conn;
    }
    return cur_raw_conn;
}

AmStreamConnection* AmMediaTransport::findRtpConnection(struct sockaddr_storage* addr)
{
    AmLock l(connections_mut);
    for(auto& conn : connections) {
        switch(conn->getConnType()) {
            case AmRawConnection::RTP_CONN:
            case AmRawConnection::ZRTP_CONN:
                if(conn->isAddrConnection(addr))
                    return conn;

            default: break;
        }
    }

    return nullptr;
}

string AmMediaTransport::getRHost(bool rtcp)
{
    auto c = getSuitableConnection(rtcp);
    if(c) return c->getRHost();
    return "";
}

int AmMediaTransport::getRPort(bool rtcp)
{
    auto c = getSuitableConnection(rtcp);
    if(c) return c->getRPort();
    return 0;
}

void AmMediaTransport::getRAddr(bool rtcp, sockaddr_storage* addr)
{
    auto c = getSuitableConnection(rtcp);
    if(c) c->getRAddr(addr);
}

void AmMediaTransport::getRAddr(sockaddr_storage* addr)
{
    if(cur_raw_conn) cur_raw_conn->getRAddr(addr);
}

int AmMediaTransport::hasLocalSocket()
{
    return l_sd;
}

int AmMediaTransport::getLocalSocket(bool reinit)
{
    CLASS_DBG("> getLocalSocket(%d)", reinit);

    if(l_sd) {
        if(!reinit) {
            CLASS_DBG("< return existent l_sd:%d", l_sd);
            return l_sd;
        } else {
            if(am_get_port(&l_saddr))
                AmConfig.media_ifs[l_if].proto_info[lproto_id]->freeRtpAddress(l_saddr);
            close(l_sd);
            l_sd = 0;
        }
    }

    int sd = 0;
    if((sd = socket(AmConfig.media_ifs[l_if].proto_info[lproto_id]->type_ip == AT_V4 ? AF_INET : AF_INET6,
                    SOCK_DGRAM,0)) == -1) {
        CLASS_ERROR("< %s",strerror(errno));
        throw string ("while creating new socket.");
    }
    SOCKET_LOG("[%p] socket(l_saddr.ss_family(%d),SOCK_DGRAM,0) = %d",
               to_void(this), l_saddr.ss_family,sd);

    int true_opt = 1;
    if(ioctl(sd, FIONBIO , &true_opt) == -1) {
        CLASS_ERROR("< %s",strerror(errno));
        close(sd);
        throw string ("while setting RTP socket non blocking.");
    }

    if(setsockopt(sd,SOL_SOCKET,SO_TIMESTAMP,
                  static_cast<void*>(&true_opt), sizeof(true_opt)) < 0)
    {
        CLASS_ERROR("< %s",strerror(errno));
        close(sd);
        throw string ("while setting RTP socket SO_TIMESTAMP opt");
    }

    if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR,
        static_cast<void*>(&true_opt), sizeof (true_opt)) == -1)
    {
        ERROR("%s",strerror(errno));
        close(sd);
        sd = 0;
        throw string ("while setting local address reusable.");
    }

    int tos = AmConfig.getMediaProtoInfo(l_if, lproto_id).tos_byte;
    if(tos &&
        setsockopt(sd, IPPROTO_IP, IP_TOS,  &tos, sizeof(tos)) == -1)
    {
        CLASS_WARN("failed to set IP_TOS for descriptors %d",sd);
    }

    l_sd = sd;

    CLASS_DBG("< return newly created l_sd:%d", l_sd);
    return l_sd;
}

void AmMediaTransport::getSdpOffer(SdpMedia& offer)
{
    CLASS_DBG("AmMediaTransport::getSdpOffer");

    //set offer type
    switch(offer.transport) {
    case TP_UDPTL:
    case TP_UDPTLSUDPTL:
        offer.type = MT_IMAGE;
        break;
    default:
        offer.type = MT_AUDIO;
    }

    //process failovers
    switch(offer.transport) {
    case TP_RTPSAVP:
    case TP_RTPSAVPF:
        if(!srtp_enable) {
            CLASS_WARN("SRTP is disabled on related interface (%s). failover to RTPAVP profile",
                AmConfig.getMediaIfaceInfo(l_if).name.c_str());
            offer.transport = TP_RTPAVP;
        }
        break;
    case TP_UDPTLSRTPSAVP:
    case TP_UDPTLSRTPSAVPF:
        if(!dtls_enable) {
            CLASS_WARN("DTLS is disabled on related interface (%s). failover to RTPAVP profile",
                AmConfig.getMediaIfaceInfo(l_if).name.c_str());
            offer.transport = TP_RTPAVP;
        }
        break;
    default:
        break;
    }

    //init related options
    switch(offer.transport) {
    case TP_RTPSAVP:
    case TP_RTPSAVPF:
        if(local_crypto.empty()) {
            int i = 0;
            for(auto profile : allowed_srtp_profiles) {
                SdpCrypto crypto;
                crypto.profile = profile;
                std::string key = AmSrtpConnection::gen_base64_key(static_cast<srtp_profile_t>(crypto.profile));
                if(key.empty()) {
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
    case TP_UDPTLSRTPSAVPF: {
        if(local_dtls_fingerprint.hash.empty()) {
            srtp_fingerprint_p fp = DtlsContext::gen_fingerprint(server_settings);
            local_dtls_fingerprint.hash = fp.hash;
            local_dtls_fingerprint.value = fp.value;
        }
        offer.fingerprint = local_dtls_fingerprint;
        offer.setup = S_ACTPASS;
    } break;
    case TP_UDPTL: {
        t38_options_t options;
        options.getT38DefaultOptions();
        options.getAttributes(offer);
        offer.payloads.clear();
        offer.fmt = T38_FMT;
    } break;
    case TP_UDPTLSUDPTL: {
        if(local_dtls_fingerprint.hash.empty()) {
            srtp_fingerprint_p fp = DtlsContext::gen_fingerprint(server_settings);
            local_dtls_fingerprint.hash = fp.hash;
            local_dtls_fingerprint.value = fp.value;
        }
        offer.fingerprint = local_dtls_fingerprint;
        offer.setup = S_ACTPASS;
        t38_options_t options;
        options.getT38DefaultOptions();
        options.getAttributes(offer);
        offer.payloads.clear();
        offer.fmt = T38_FMT;
    } break;
    default:
#ifdef WITH_ZRTP
        if(stream->isZrtpEnabled() && zrtp_enable) {
            offer.zrtp_hash.hash = stream->getZrtpContext()->getLocalHash(stream->get_ssrc());
            if(!offer.zrtp_hash.hash.empty()) offer.zrtp_hash.is_use = true;
        }
#endif/*WITH_ZRTP*/
        break;
    }
}

void AmMediaTransport::getSdpAnswer(const SdpMedia& offer, SdpMedia& answer)
{
    CLASS_DBG("AmMediaTransport::getSdpAnswer");

    int transport = offer.transport;
    if(transport != TP_UDPTL && transport != TP_UDPTLSUDPTL)
        answer.type = MT_AUDIO;
    else
        answer.type = MT_IMAGE;

    if((offer.is_simple_srtp() && !srtp_enable) ||
       (offer.is_dtls_srtp() && !dtls_enable))
    {
        std::string error(offer.is_simple_srtp() ? "SRTP": "DTLS");
        error += " transport is not supported";
        CLASS_ERROR("[%s] %s on interface(%d/%s)",
            stream ? stream->getSessionLocalTag() : "null",
            error.c_str(), l_if,
            AmConfig.media_ifs[l_if].proto_info[lproto_id]->transportToStr().c_str());
        throw AmSession::Exception(488, error);
    } else if(transport == TP_RTPSAVP || transport == TP_RTPSAVPF) {
        if(offer.crypto.empty()) {
            throw AmSession::Exception(488,"absent crypto attribute");
        }
        //TODO: check intersection with SDP offer if local_crypto is not empty
        if(local_crypto.empty()) {
            for(const auto &allowed_profile : allowed_srtp_profiles) {
                for(const auto &offer_crypto : offer.crypto) {
                    if(allowed_profile == offer_crypto.profile) {
                        local_crypto.emplace_back(offer_crypto);
                        auto &c = local_crypto.back();
                        c.keys.clear();
                        c.keys.emplace_back(
                            SdpKeyInfo(AmSrtpConnection::gen_base64_key(
                                static_cast<srtp_profile_t>(c.profile))));
                        break;
                    }
                }
                if(!local_crypto.empty()) break;
            }
        }
        if(local_crypto.empty()) {
            throw AmSession::Exception(488,"no compatible srtp profile");
        }
        answer.crypto = local_crypto;
    } else if(transport == TP_UDPTLSRTPSAVP || transport == TP_UDPTLSRTPSAVPF) {
        dtls_settings* settings = (offer.setup == S_ACTIVE) ?
                                                    static_cast<dtls_settings*>(server_settings) :
                                                    static_cast<dtls_settings*>(client_settings);
        if(local_dtls_fingerprint.hash.empty()) {
            srtp_fingerprint_p fp = DtlsContext::gen_fingerprint(settings);
            local_dtls_fingerprint.hash = fp.hash;
            local_dtls_fingerprint.value = fp.value;
        }
        answer.fingerprint = local_dtls_fingerprint;
        answer.setup = S_PASSIVE;
        if(offer.setup == S_PASSIVE)
            answer.setup = S_ACTIVE;
        else if(offer.setup == S_HOLD)
            throw AmSession::Exception(488,"hold connections");
        else if(offer.setup == S_UNDEFINED)
            throw AmSession::Exception(488,"setup not defined");
    } else if(transport == TP_UDPTL) {
        t38_options_t options;
        options.negotiateT38Options(offer.attributes);
        options.getAttributes(answer);
        answer.payloads.clear();
        answer.fmt = T38_FMT;
    } else if(transport == TP_UDPTLSUDPTL) {
        dtls_settings* settings = (offer.setup == S_ACTIVE) ?
                                                    static_cast<dtls_settings*>(server_settings) :
                                                    static_cast<dtls_settings*>(client_settings);
        if(local_dtls_fingerprint.hash.empty()) {
            srtp_fingerprint_p fp = DtlsContext::gen_fingerprint(settings);
            local_dtls_fingerprint.hash = fp.hash;
            local_dtls_fingerprint.value = fp.value;
        }
        answer.fingerprint = local_dtls_fingerprint;
        answer.setup = S_PASSIVE;
        if(offer.setup == S_PASSIVE)
            answer.setup = S_ACTIVE;
        else if(offer.setup == S_HOLD)
            throw AmSession::Exception(488,"hold connections");
        else if(offer.setup == S_UNDEFINED)
            throw AmSession::Exception(488,"setup not defined");
        t38_options_t options;
        options.negotiateT38Options(offer.attributes);
        options.getAttributes(answer);
        answer.payloads.clear();
        answer.fmt = T38_FMT;
#ifdef WITH_ZRTP
    } else if(stream->isZrtpEnabled() && zrtp_enable) {
        answer.zrtp_hash.hash = stream->getZrtpContext()->getLocalHash(stream->get_ssrc());
        if(!answer.zrtp_hash.hash.empty()) answer.zrtp_hash.is_use = true;
#endif/*WITH_ZRTP*/
    }
}

void AmMediaTransport::getIceCandidate(SdpMedia& media)
{
    SdpIceCandidate candidate;
    candidate.conn.network = NT_IN;
    candidate.comp_id = type;
    candidate.conn.addrType = (l_saddr.ss_family == AF_INET) ? AT_V4 : AT_V6;
    candidate.conn.address = am_inet_ntop(&l_saddr) + " " + int2str(l_port);
    media.ice_candidate.push_back(candidate);
    ice_cred.lpriority = candidate.priority;
}

uint32_t AmMediaTransport::getCurrentConnectionPriority()
{
    if(allowed_ice_addrs.empty()) return 0;
    return allowed_ice_addrs.rbegin()->first;
}

void AmMediaTransport::initIceConnection(const SdpMedia& local_media, const SdpMedia& remote_media, bool sdp_offer_owner)
{
    CLASS_DBG("initIceConnection() stream:%p, state:%s", to_void(stream), state2str().c_str());
    if(state == TRANSPORT_STATE_NONE) {
        state = TRANSPORT_STATE_ICE_INIT;
        store_ice_cred(local_media, remote_media);

        if(local_media.is_simple_srtp() && srtp_enable)
            store_srtp_cred(local_media, remote_media);

        initStunConnections(remote_media.ice_candidate, sdp_offer_owner);

    } else if (ice_cred.ruser != remote_media.ice_ufrag || ice_cred.rpassword != remote_media.ice_pwd) {
        state = TRANSPORT_STATE_ICE_RESTART;
        store_ice_cred(local_media, remote_media);
        initStunConnections(remote_media.ice_candidate, sdp_offer_owner);
    }
}

void AmMediaTransport::initStunConnections(const vector<SdpIceCandidate>& candidates, bool sdp_offer_owner)
{
    CLASS_DBG("initStunConnections state:%s, type:%s", state2str().c_str(), type2str().c_str());
    // remove old stun connections if needed
    switch(state) {
        case TRANSPORT_STATE_ICE_INIT:
        case TRANSPORT_STATE_ICE_RESTART:
        removeAllConnection(AmStreamConnection::STUN_CONN);
        allowed_ice_addrs.clear(); // drop allowed_ice_addrs
        break;
    default:
        break;
    }

    for(auto candidate : candidates) {
        if(candidate.transport != ICTR_UDP)
            continue;

        string addr = candidate.conn.address;
        vector<string> addr_port = explode(addr, " ");

        if(addr_port.size() != 2) continue;
        string address = addr_port[0];
        int port = 0;
        str2int(addr_port[1], port);

        if(type != candidate.comp_id)
            continue;

        if(l_saddr.ss_family != (candidate.conn.addrType == AT_V4 ? AF_INET : AF_INET6))
            continue;

        try {
            auto conn = (AmStunConnection *)addStunConnection(address, port, ice_cred.lpriority, candidate.priority);
            conn->send_request();
        } catch(string& error) {
            CLASS_ERROR("ICE candidate STUN connection error: %s", error.c_str());
        }
    }
}

void AmMediaTransport::initRtpConnection(const string& remote_address, int remote_port)
{
    CLASS_DBG("initRtpConnection(%s, %d) stream:%p, state:%s, type:%s",
              remote_address.data(), remote_port,
              to_void(stream), state2str().c_str(), type2str().c_str());

    CLASS_DBG("AmMediaTransport::initRtpConnection(%s, %d) stream:%p, state:%s, type:%s, cur_rtp_conn:%p",
              remote_address.data(), remote_port, to_void(stream), state2str().c_str(), type2str().c_str(), cur_rtp_conn);
    if(state == TRANSPORT_STATE_NONE) {
        state = TRANSPORT_STATE_RTP;
        if(type == RTP_TRANSPORT)
            addRtpConnection(remote_address, remote_port);

        addRtcpConnection(remote_address, remote_port);
    } else {
        if(state != TRANSPORT_STATE_RTP) {
            CLASS_WARN("incorrect state:%s, must be `TRANSPORT_STATE_RTP`", state2str().c_str());
        }
        if(cur_rtp_conn) {
            CLASS_DBG("setRAddr for cur_rtp_conn %p", cur_rtp_conn);
            cur_rtp_conn->setRAddr(remote_address, remote_port);
        } else {
            CLASS_DBG("setRAddr for all RTP connections");
            AmLock l(connections_mut);
            for(auto &c : connections) {
               if(c->getConnType()==AmStreamConnection::RTP_CONN) {
                   c->setRAddr(remote_address, remote_port);
               }
            }
        }
        if(cur_rtcp_conn) {
            CLASS_DBG("setRAddr for cur_rtcp_conn %p", cur_rtcp_conn);
            cur_rtcp_conn->setRAddr(remote_address, remote_port);
        } else {
            CLASS_DBG("setRAddr for all RTCP connections");
            AmLock l(connections_mut);
            for(auto &c : connections) {
               if(c->getConnType()==AmStreamConnection::RTCP_CONN) {
                   c->setRAddr(remote_address, remote_port);
               }
            }
        }
        if(cur_raw_conn) {
            cur_raw_conn->setRAddr(remote_address, remote_port);
        }
    }
}

void AmMediaTransport::initSrtpConnection(const string& remote_address, int remote_port, const SdpMedia& local_media, const SdpMedia& remote_media)
{
    if(!srtp_enable) return;

    CLASS_DBG("initSrtpConnection() stream:%p, state:%s, type:%s", to_void(stream), state2str().c_str(), type2str().c_str());

    if(state == TRANSPORT_STATE_NONE) {
        state = TRANSPORT_STATE_RTP;

        if(store_srtp_cred(local_media, remote_media) < 0)
            return;

        if(type == RTP_TRANSPORT)
            addSrtpConnection(remote_address, remote_port);

        addSrtcpConnection(remote_address, remote_port);
    } else {
        if(cur_rtp_conn) {
            CLASS_DBG("update SRTP connection endpoint");
            cur_rtp_conn->setRAddr(remote_address, remote_port);

            if(AmSrtpConnection* conn = dynamic_cast<AmSrtpConnection *>(cur_rtp_conn)) {
                 updateKeys(conn, local_media, remote_media);
            }
        }
        if(cur_rtcp_conn) {
            CLASS_DBG("update SRTCP connection endpoint");
            cur_rtcp_conn->setRAddr(remote_address, remote_port);

            if(AmSrtpConnection* conn = dynamic_cast<AmSrtpConnection *>(cur_rtcp_conn)) {
                 updateKeys(conn, local_media, remote_media);
            }
        }
        if(cur_raw_conn) {
            cur_raw_conn->setRAddr(remote_address, remote_port);
        }
    }
}

void AmMediaTransport::initSrtpConnection(uint16_t srtp_profile, const string& local_key, const string& remote_key)
{
    if(!srtp_enable) return;

    CLASS_DBG("initSrtpConnection() stream:%p, state:%s, type:%s", to_void(stream), state2str().c_str(), type2str().c_str());

    //store_srtp_cred(srtp_profile, local_key, srtp_master_keys(remote_key));
    srtp_master_keys remote_keys = srtp_master_keys(remote_key);

    vector<sockaddr_storage> addrs;
    {
        AmLock l(connections_mut);
        for(auto conn : connections) {
            if(state == TRANSPORT_STATE_ICE_DTLS ||
               state == TRANSPORT_STATE_ICE_RESTART) {
                if(conn->getConnType() == AmStreamConnection::STUN_CONN) {
                    sockaddr_storage raddr;
                    conn->getRAddr(&raddr);
                    addrs.push_back(raddr);
                }
            } else if(state == TRANSPORT_STATE_DTLS) {
                if(conn->getConnType() == AmStreamConnection::DTLS_CONN) {
                    sockaddr_storage raddr;
                    conn->getRAddr(&raddr);
                    addrs.push_back(raddr);
                }
            } else if(state == TRANSPORT_STATE_ZRTP) {
                if(conn->getConnType() == AmStreamConnection::ZRTP_CONN) {
                    cur_rtp_conn = 0;
                    sockaddr_storage raddr;
                    conn->getRAddr(&raddr);
                    addrs.push_back(raddr);
                }
            } else {
                CLASS_WARN("incorrect state in called function, ignore it");
            }
        }
    }

    for(auto addr : addrs) {
        if(type == RTP_TRANSPORT)
            addSrtpConnection(am_inet_ntop(&addr), am_get_port(&addr), srtp_profile, local_key, remote_keys);

        addSrtcpConnection(am_inet_ntop(&addr), am_get_port(&addr), srtp_profile, local_key, remote_keys);
    }

    switch(state) {
        case TRANSPORT_STATE_ICE_SRTP:
            return;
        case TRANSPORT_STATE_ICE_RESTART:
        case TRANSPORT_STATE_ICE_DTLS:
        case TRANSPORT_STATE_ICE_RTP:
            state = TRANSPORT_STATE_ICE_SRTP;
            break;
        default:
            state = TRANSPORT_STATE_RTP;
    }
}

void AmMediaTransport::updateKeys(AmSrtpConnection* conn, const SdpMedia& local_media, const SdpMedia& remote_media)
{
    if(store_srtp_cred(local_media, remote_media) < 0)
        return;

    updateKeys(conn, srtp_cred.srtp_profile,
               srtp_cred.local_key, srtp_cred.remote_keys);
}

void AmMediaTransport::updateKeys(
    AmSrtpConnection* conn,
    uint16_t srtp_profile,
    const string& local_key,
    const srtp_master_keys& remote_keys)
{
    conn->update_keys(static_cast<srtp_profile_t>(srtp_profile), local_key, remote_keys);
}

void AmMediaTransport::initDtlsConnection(const string& remote_address, int remote_port, const SdpMedia& local_media, const SdpMedia& remote_media)
{
    if(!dtls_enable) return;

    CLASS_DBG("initDtlsConnection() stream:%p, state:%s, type:%s", to_void(stream), state2str().c_str(), type2str().c_str());

    if(state == TRANSPORT_STATE_NONE) {
        auto dtls_context = stream->getDtlsContext(type);
        if(dtls_context) {
            state = TRANSPORT_STATE_DTLS;
            addDtlsConnection(remote_address, remote_port, dtls_context);
        }
    } else {
        CLASS_DBG("update DTLS connection endpoint");
        for(auto& c : connections) {
            if (c->getConnType() == AmStreamConnection::DTLS_CONN ||
                c->getConnType() == AmStreamConnection::RTP_CONN  ||
                c->getConnType() == AmStreamConnection::RTCP_CONN ) {
                    c->setRAddr(remote_address, remote_port);
            }
        }
    }
}

void AmMediaTransport::initUdptlConnection(const string& remote_address, int remote_port)
{
    if(state == TRANSPORT_STATE_NONE || state == TRANSPORT_STATE_RTP) {
        state = TRANSPORT_STATE_UDPTL;
        addConnection(new UDPTLConnection(this, remote_address, remote_port));
        mode = TRANSPORT_MODE_FAX;
        cur_udptl_conn = connections.back();
    } else if(state == TRANSPORT_STATE_DTLS) {
        state = TRANSPORT_STATE_UDPTL;
        {
        AmLock l(connections_mut);
            for(auto &conn : connections) {
                if(conn->getConnType() == AmStreamConnection::DTLS_CONN) {
                    connections.push_back(new DTLSUDPTLConnection(this, remote_address, remote_port, conn));
                }
            }
        }
        mode = TRANSPORT_MODE_DTLS_FAX;
    }
}

#ifdef WITH_ZRTP
void AmMediaTransport::initZrtpConnection(const string& remote_address, int remote_port)
{
    CLASS_DBG("initZrtpConnection() stream:%p, state:%s, type:%s", to_void(stream), state2str().c_str(), type2str().c_str());

    try {
        if(state == TRANSPORT_STATE_NONE) {
            state = TRANSPORT_STATE_ZRTP;
            cur_rtp_conn = addZrtpConnection(remote_address, remote_port);
        } else if(state == TRANSPORT_STATE_ZRTP){
            CLASS_DBG("update ZRTP connection endpoint");
            cur_rtp_conn->setRAddr(remote_address, remote_port);
        }
    } catch(string& error) {
        CLASS_ERROR("ZRTP connection error: %s", error.c_str());
    }
}
#endif/*WITH_ZRTP*/

void AmMediaTransport::initRawConnection()
{
    DBG("initRawConnection: state:%s, type:%s", state2str().c_str(), type2str().c_str());
    setMode(TRANSPORT_MODE_RAW);
    if(state == TRANSPORT_STATE_NONE) {
        state = TRANSPORT_STATE_RAW;
    }
}

void AmMediaTransport::getInfo(AmArg& ret)
{
    if(mode == TRANSPORT_MODE_FAX) ret["mode"] = "fax";
    else if(mode == TRANSPORT_MODE_DTLS_FAX) ret["mode"] = "dtls_fax";
    else if(mode == TRANSPORT_MODE_RAW) ret["mode"] = "raw";
    else if(mode == TRANSPORT_MODE_DEFAULT) ret["mode"] = "default";

    if(type == FAX_TRANSPORT) ret["type"] = "fax";
    if(type == RTP_TRANSPORT) ret["type"] = "rtp";
    if(type == RTCP_TRANSPORT) ret["type"] = "rtcp";
    AmArg& conns = ret["connections"];
    AmLock l(connections_mut);
    for(auto& connection : connections) {
        AmArg conn;
        connection->getInfo(conn);
        conns.push(conn);
    }
}

void AmMediaTransport::addConnection(AmStreamConnection* conn)
{
    AmLock l(connections_mut);
    connections.push_back(conn);
}

void AmMediaTransport::removeConnection(AmStreamConnection* conn)
{
    AmLock l(connections_mut);
    for(auto conn_it = connections.begin(); conn_it != connections.end(); conn_it++) {
        if(*conn_it == conn) {
            connections.erase(conn_it);
            delete conn;
            break;
        }
    }
}

void AmMediaTransport::removeAllConnection(AmStreamConnection::ConnectionType type)
{
    CLASS_DBG("removeAllConnection, conn_type:%s, state:%s, type:%s",
              AmStreamConnection::connType2Str(type).c_str(),
              state2str().c_str(), type2str().c_str());

    AmLock l(connections_mut);
    for(auto it = connections.begin(); it != connections.end();) {
        auto conn = *it;
        if(conn->getConnType() == type) {
            it = connections.erase(it);
            delete conn;
            continue;
        }

        ++it;
    }
}

void AmMediaTransport::allowStunConnection(sockaddr_storage* remote_addr, uint32_t priority)
{
    const string remote_address = am_inet_ntop(remote_addr);
    const int remote_port = am_get_port(remote_addr);
    CLASS_DBG("allow stun connection by addr:%s, port:%d, state:%s, type:%s",
              remote_address.c_str(), remote_port, state2str().c_str(), type2str().c_str());

    if(remote_addr->ss_family != l_saddr.ss_family) return;

    if(state == TRANSPORT_STATE_ICE_RESTART) {
        allowed_ice_addrs.clear();
        cur_rtp_conn = 0;
        cur_rtcp_conn = 0;

        removeAllConnection(AmStreamConnection::RTP_CONN);
        removeAllConnection(AmStreamConnection::RTCP_CONN);
        removeAllConnection(AmStreamConnection::DTLS_CONN);
        removeAllConnection(AmStreamConnection::ZRTP_CONN);
        state = TRANSPORT_STATE_ICE_INIT;
    }

    if(state == TRANSPORT_STATE_ICE_INIT) {
        auto dtls_context = stream->getDtlsContext(type);
        if(dtls_context) {
            state = TRANSPORT_STATE_ICE_DTLS;
            addDtlsConnection(remote_address, remote_port, dtls_context);
        } else {
            state = TRANSPORT_STATE_ICE_RTP;

            if(srtp_cred.srtp_profile > srtp_profile_reserved) {
                if(type == RTP_TRANSPORT)
                    addSrtpConnection(remote_address, remote_port);

                addSrtcpConnection(remote_address, remote_port);
            #ifdef WITH_ZRTP
            } else if(stream->isZrtpEnabled() && zrtp_enable) {
                addZrtpConnection(remote_address, remote_port);
            #endif
            } else {
                if(type == RTP_TRANSPORT)
                    addRtpConnection(remote_address, remote_port);

                addRtcpConnection(remote_address, remote_port);
            }
        }
    }

    allowed_ice_addrs.emplace(priority, *remote_addr);
    sockaddr_storage target_addr = allowed_ice_addrs.rbegin()->second;
    cur_rtp_conn = findRtpConnection(&target_addr);
}

void AmMediaTransport::dtls_alert(string alert)
{
    CLASS_ERROR("DTLS alert %s", alert.c_str());
}

void AmMediaTransport::onRtpPacket(AmRtpPacket* packet, AmStreamConnection* conn)
{
    if(!cur_rtp_conn)
        cur_rtp_conn = conn;
    stream->onRtpPacket(packet, this);
}

void AmMediaTransport::onRtcpPacket(AmRtpPacket* packet, AmStreamConnection* conn)
{
    if(!cur_rtcp_conn)
        cur_rtcp_conn = conn;
    stream->onRtcpPacket(packet, this);
}

void AmMediaTransport::onRawPacket(AmRtpPacket* packet, AmStreamConnection* conn)
{
    if(mode == TRANSPORT_MODE_DEFAULT) {
        onPacket(packet->getBuffer(), packet->getBufferSize(), packet->saddr, packet->recv_time);
        stream->freeRtpPacket(packet);
    } else if(mode == TRANSPORT_MODE_FAX || mode == TRANSPORT_MODE_DTLS_FAX) {
        cur_udptl_conn = conn;
        stream->onUdptlPacket(packet, this);
    } else {
        cur_raw_conn = conn;
        stream->onRawPacket(packet, this);
    }
}

void AmMediaTransport::updateStunTimers()
{
    AmLock l(connections_mut);
    for(auto conn : connections) {
        if(conn->getConnType() == AmStreamConnection::STUN_CONN)
            static_cast<AmStunConnection*>(conn)->updateStunTimer();
    }
}

void AmMediaTransport::stopReceiving()
{
    AmLock l(stream_mut);
    CLASS_DBG("stopReceiving() l_sd:%d, state:%s, type:%s", l_sd, state2str().c_str(), type2str().c_str());
    if(hasLocalSocket() && state != TRANSPORT_STATE_NONE) {
        CLASS_DBG("remove stream %p %s transport from RTP receiver",
            to_void(stream), transport_type2str(getTransportType()));
        AmRtpReceiver::instance()->removeStream(getLocalSocket(),l_sd_ctx);
        l_sd_ctx = -1;
    }
}

void AmMediaTransport::resumeReceiving()
{
    AmLock l(stream_mut);
    CLASS_DBG("resumeReceiving() l_sd:%d, state:%s, type:%s", l_sd, state2str().c_str(), type2str().c_str());
    if(hasLocalSocket() && state != TRANSPORT_STATE_NONE) {
        CLASS_DBG("add/resume stream %p %s transport into RTP receiver",
            to_void(stream), transport_type2str(getTransportType()));
        l_sd_ctx = AmRtpReceiver::instance()->addStream(l_sd, this, l_sd_ctx);
        if(l_sd_ctx < 0) {
            CLASS_DBG("error on add/resuming stream. l_sd_ctx = %d", l_sd_ctx);
        }
    }
}

void AmMediaTransport::setPassiveMode(bool p)
{
    AmLock l(connections_mut);
    for(auto conn : connections) {
        conn->setPassiveMode(p);
    }
}

void AmMediaTransport::log_rcvd_packet(const char *buffer, int len, struct sockaddr_storage &recv_addr, AmStreamConnection::ConnectionType type)
{
    static const cstring empty;
    if (logger)
        logger->log(buffer, len, &recv_addr, &l_saddr, empty);
    if (sensor)
        sensor->feed(buffer, static_cast<int>(b_size), &saddr, &l_saddr, streamConnType2sensorPackType(type));
}

void AmMediaTransport::log_sent_packet(const char *buffer, int len, struct sockaddr_storage &send_addr, AmStreamConnection::ConnectionType type)
{
    static const cstring empty;
    if (logger)
        logger->log(buffer, len, &l_saddr, &send_addr, empty);
    if (sensor)
        sensor->feed(buffer, static_cast<int>(b_size), &l_saddr, &send_addr, streamConnType2sensorPackType(type));
}

ssize_t AmMediaTransport::send(AmRtpPacket* packet, AmStreamConnection::ConnectionType type)
{
    //CLASS_DBG("send(%p,%d)", packet, type);
    AmStreamConnection* cur_stream = nullptr;
    if(type == AmStreamConnection::RTP_CONN) {
        cur_stream = cur_rtp_conn;
    } else if(type == AmStreamConnection::RTCP_CONN) {
        cur_stream = cur_rtcp_conn;
    } else if(type == AmStreamConnection::RAW_CONN) {
        cur_stream = cur_raw_conn;
    } else if(type == AmStreamConnection::UDPTL_CONN) {
        cur_stream = cur_udptl_conn;
    }
    
    ssize_t ret = 0;
    if(cur_stream) {
        if(!cur_stream->isMute()) ret = cur_stream->send(packet);
    } else {
        AmLock l(connections_mut);
        for(auto conn : connections) {
            if(conn->isUseConnection(type) && !conn->isMute()) {
                ret = conn->send(packet);
                break;
            }
        }
    }

    if(ret > 0) {
        stream->update_sender_stats(*packet);
    }

    return ret;
}

ssize_t AmMediaTransport::send(sockaddr_storage* raddr, unsigned char* buf, int size, AmStreamConnection::ConnectionType type)
{
    /*CLASS_DBG("send(%s:%hu,%p,%d,%d)",
              get_addr_str(raddr).data(), am_get_port(raddr),
              buf,size,type);*/
    log_sent_packet(reinterpret_cast<const char*>(buf), size, *raddr, type);

    MEDIA_info* iface = AmConfig.media_ifs[static_cast<size_t>(l_if)]
        .proto_info[static_cast<size_t>(lproto_id)];

    if(iface->net_if_idx) {
        if(iface->sig_sock_opts&trsp_socket::use_raw_sockets) {
            return raw_sender::send(
                reinterpret_cast<char*>(buf),static_cast<unsigned int>(size),
                static_cast<int>(iface->net_if_idx),
                &l_saddr,
                raddr,
                iface->tos_byte);
        }
        //TODO: process case with AmConfig.force_outbound_if properly for rtcp
        if(AmConfig.force_outbound_if) {
            return sendmsg(buf,size);
        }
    }

    ssize_t err = ::sendto(
        l_sd, buf, static_cast<size_t>(size), 0,
        reinterpret_cast<const struct sockaddr*>(raddr), SA_len(raddr));

    if(err == -1) {
        CLASS_ERROR("sendto(%d,%p,%d,0,%p,%ld): errno: %d, raddr:'%s', type: %d",
            l_sd,
            static_cast<void *>(buf),size,
            static_cast<void *>(raddr),SA_len(raddr),
            errno, get_addr_str(raddr).data(), type);
        log_stacktrace(L_DBG);
        return -1;
    }
    return err;
}

int AmMediaTransport::sendmsg(unsigned char* buf, int size)
{
    MEDIA_info &iface = AmConfig.getMediaProtoInfo(l_if, lproto_id);
    unsigned int sys_if_idx = iface.net_if_idx;

    struct msghdr hdr;
    struct cmsghdr* cmsg;

    union {
        char cmsg4_buf[CMSG_SPACE(sizeof(struct in_pktinfo))];
        char cmsg6_buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    } cmsg_buf;

    struct iovec msg_iov[1];
    msg_iov[0].iov_base = to_void(buf);
    msg_iov[0].iov_len  = static_cast<size_t>(size);

    bzero(&hdr,sizeof(hdr));
    hdr.msg_name = to_void(&l_saddr);
    hdr.msg_namelen = SA_len(&l_saddr);
    hdr.msg_iov = msg_iov;
    hdr.msg_iovlen = 1;

    bzero(&cmsg_buf,sizeof(cmsg_buf));
    hdr.msg_control = &cmsg_buf;
    hdr.msg_controllen = sizeof(cmsg_buf);

    cmsg = CMSG_FIRSTHDR(&hdr);
    if(l_saddr.ss_family == AF_INET) {
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

        struct in_pktinfo* pktinfo = reinterpret_cast<struct in_pktinfo*>(CMSG_DATA(cmsg));
        pktinfo->ipi_ifindex = static_cast<int>(sys_if_idx);
    }
    else if(l_saddr.ss_family == AF_INET6) {
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

        struct in6_pktinfo* pktinfo = reinterpret_cast<struct in6_pktinfo*>(CMSG_DATA(cmsg));
        pktinfo->ipi6_ifindex = sys_if_idx;
    }

    hdr.msg_controllen = cmsg->cmsg_len;

    // bytes_sent = ;
    if(::sendmsg(l_sd, &hdr, 0) < 0) {
        ERROR("sendto: %s",strerror(errno));
        return -1;
    }

    return 0;
}

ssize_t AmMediaTransport::recv(int sd)
{
    cmsghdr *cmsgptr;
    ssize_t ret = recvmsg(sd,&recv_msg,0);

    for (cmsgptr = CMSG_FIRSTHDR(&recv_msg);
        cmsgptr != nullptr;
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
        b_size = static_cast<unsigned int>(ret);
    }

    return ret;
}

void AmMediaTransport::recvPacket(int fd)
{
    if(recv(fd) > 0) {
        trsp_acl::action_t action = media_acl.check(saddr);
        if(action == trsp_acl::Allow)
            onPacket(buffer, b_size, saddr, recv_time);
        else {
            stream->inc_drop_pack();
            AmRtpReceiver::instance()->inc_drop_packets();
        }
    }
}

void AmMediaTransport::onPacket(unsigned char* buf, unsigned int size, sockaddr_storage& addr, struct timeval recvtime)
{
    stream->updateRcvdBytes(size);
    AmStreamConnection::ConnectionType ctype;
    if(mode == TRANSPORT_MODE_DEFAULT) {
        ctype = GetConnectionType(buf, size);
        if(ctype == AmStreamConnection::UNKNOWN_CONN) {
            CLASS_WARN("Unknown packet type from %s:%d, ignore it",
                       am_inet_ntop(&addr).c_str(),
                       am_get_port(&addr));
            return;
        }
    } else if(mode == TRANSPORT_MODE_FAX){
        ctype = AmStreamConnection::UDPTL_CONN;
    } else if(mode == TRANSPORT_MODE_DTLS_FAX) {
        ctype = AmStreamConnection::DTLS_CONN;
    } else {
        ctype = AmStreamConnection::RAW_CONN;
    }

    log_rcvd_packet(reinterpret_cast<const char*>(buf), static_cast<int>(size), addr, ctype);

    vector<AmStreamConnection*> conns_by_type;
    AmStreamConnection* s_conn = nullptr;

    {
        AmLock l(connections_mut);
        for(auto conn : connections) {
            if(conn->isUseConnection(ctype)) {
                conns_by_type.push_back(conn);
            }
        }

        for(auto conn : conns_by_type) {
            if(conn->isAddrConnection(&addr)) {
                s_conn = conn;
                break;
            }
        }

        if (!s_conn && !conns_by_type.empty()
            && ctype != AmStreamConnection::STUN_CONN)
        {
            s_conn = conns_by_type[0];
        }
    }

    if(!s_conn) {
        if(ctype == AmStreamConnection::STUN_CONN && stream->isIceStream()) {
            uint32_t lpriority = (ICT_HOST << 24) | ((rand() & 0xffff) << 8) | (256 - type);
            s_conn = addStunConnection(am_inet_ntop(&addr), am_get_port(&addr), lpriority);
        } else return;
    }

    s_conn->process_packet(buf, size, &addr, recvtime);
}

int AmMediaTransport::getSrtpCredentialsBySdp(
    const SdpMedia& local_media, const SdpMedia& remote_media,
    string& l_key, srtp_master_keys& r_keys)
{
    CryptoProfile cprofile = CP_NONE;
    if(local_media.crypto.size() == 1) {
        cprofile = local_media.crypto[0].profile;
    } else if(remote_media.crypto.size() == 1) {
        cprofile = remote_media.crypto[0].profile;
    } else if(local_media.crypto.empty()){
        CLASS_ERROR("local secure audio stream without encryption details");
        return -1;
    } else if(remote_media.crypto.empty()){
        CLASS_ERROR("remote secure audio stream without encryption details");
        return -1;
    } else {
        CLASS_WARN("secure audio stream with some encryption details, use local first");
        cprofile = local_media.crypto[0].profile;
    }

    unsigned char local_key[SRTP_KEY_SIZE], remote_key[SRTP_KEY_SIZE];
    unsigned int local_key_size = SRTP_KEY_SIZE, remote_key_size = SRTP_KEY_SIZE;

    //get local key
    auto local_crypto_profile_it = std::find_if(local_media.crypto.begin(), local_media.crypto.end(),
        [cprofile](const SdpCrypto &s){ return s.profile == cprofile; });
    if(local_crypto_profile_it == local_media.crypto.end()) {
        CLASS_ERROR("no chosen profile %s in local media crypto attributes",
                    SdpCrypto::profile2str(cprofile).data());
        return -1;
    }
    if(local_crypto_profile_it->keys.empty()) {
        CLASS_ERROR("local secure audio stream without master key");
        return -1;
    }

    //reduce local_crypto vector to the chosen profile (to generate correct answer for reINVITES)
    local_crypto.insert(local_crypto.begin(), *local_crypto_profile_it);
    local_crypto.resize(1);

    AmSrtpConnection::base64_key(local_crypto_profile_it->keys[0].key, local_key, local_key_size);
    l_key.assign(reinterpret_cast<char *>(local_key), local_key_size);

    //get remote key
    auto remote_crypto_profile_it = std::find_if(remote_media.crypto.begin(), remote_media.crypto.end(),
        [cprofile](const SdpCrypto &s){ return s.profile == cprofile; });
    if(remote_crypto_profile_it == remote_media.crypto.end()) {
        CLASS_ERROR("no chosen profile %s in remote media crypto attributes",
                    SdpCrypto::profile2str(cprofile).data());
        return -1;
    }
    if(remote_crypto_profile_it->keys.empty()) {
        CLASS_ERROR("remote secure audio stream without master key");
        return -1;
    }
    for(auto &key : remote_crypto_profile_it->keys) {
        string rkey;
        AmSrtpConnection::base64_key(key.key, remote_key, remote_key_size);
        rkey.assign(reinterpret_cast<char *>(remote_key), remote_key_size);
        r_keys.add(rkey, key.mki.id, key.mki.len);
        if(!key.mki.len) break;
    }

    return cprofile;
}

AmStreamConnection* AmMediaTransport::addStunConnection(const string& remote_address, int remote_port,
                                                        unsigned int lpriority, unsigned int priority)
{
    CLASS_DBG("addStunConnection state:%s, type:%s, raddr:%s, rport:%d",
              state2str().c_str(), type2str().c_str(), remote_address.c_str(), remote_port);

    AmStunConnection* conn = new AmStunConnection(this, remote_address, remote_port, lpriority, priority);
    conn->set_credentials(ice_cred.luser, ice_cred.lpassword, ice_cred.ruser, ice_cred.rpassword);
    conn->set_ice_role_controlled(!stream->getSdpOfferOwner()); //rfc5245#section-5.2
    conn->updateStunTimer();
    addConnection(conn);
    return conn;
}

AmStreamConnection* AmMediaTransport::addDtlsConnection(const string& remote_address, int remote_port, DtlsContext* context)
{
    CLASS_DBG("addDtlsConnection state:%s, type:%s, raddr:%s, rport:%d",
              state2str().c_str(), type2str().c_str(), remote_address.c_str(), remote_port);

    AmDtlsConnection* conn = new AmDtlsConnection(this, remote_address, remote_port, context);
    addConnection(conn);

    if(!context->isInited()) {
        try {
            stream->initDtls(type, context->is_client);
        } catch(string& error) {
            CLASS_ERROR("DTLS connection error: %s", error.c_str());
        }
    }

    context->setCurrentConnection(conn);
    return conn;
}


AmStreamConnection* AmMediaTransport::addSrtpConnection(const string& remote_address, int remote_port)
{
    return addSrtpConnection(remote_address, remote_port,
                             srtp_cred.srtp_profile,
                             srtp_cred.local_key,
                             srtp_cred.remote_keys);
}

AmStreamConnection* AmMediaTransport::addSrtpConnection(const string& remote_address, int remote_port,
                                                        int srtp_profile, const string& local_key,
                                                        const srtp_master_keys& remote_keys)
{
    CLASS_DBG("addSrtpConnection state:%s, type:%s, raddr:%s, rport:%d",
              state2str().c_str(), type2str().c_str(), remote_address.c_str(), remote_port);

    try {
        AmSrtpConnection* conn = new AmSrtpConnection(this, remote_address, remote_port, AmStreamConnection::RTP_CONN);
        conn->use_keys(static_cast<srtp_profile_t>(srtp_profile), local_key, remote_keys);

        //TODO: remove in the future when fixed mute on ice
        if(conn->isMute()) {
            stream->setMute(conn->isMute());
        }

        //TODO: is a correct code: uncomment after fixed mute in ice
        //if(!stream->isIceStream() && conn->isMute()) {
        //    stream->setMute(true);
        //}

        addConnection(conn);
        return conn;
    } catch(string& error) {
        CLASS_ERROR("SRTP connection error: %s", error.c_str());
    }

    return nullptr;
}

AmStreamConnection* AmMediaTransport::addSrtcpConnection(const string& remote_address, int remote_port)
{
    return addSrtpConnection(remote_address, remote_port,
                             srtp_cred.srtp_profile,
                             srtp_cred.local_key,
                             srtp_cred.remote_keys);
}

AmStreamConnection* AmMediaTransport::addSrtcpConnection(const string& remote_address, int remote_port,
                                                         int srtp_profile, const string& local_key,
                                                         const srtp_master_keys& remote_keys)
{
    CLASS_DBG("addSrtcpConnection state:%s, type:%s, raddr:%s, rport:%d",
              state2str().c_str(), type2str().c_str(), remote_address.c_str(), remote_port);

    try {
        AmSrtpConnection* conn = new AmSrtpConnection(this, remote_address, remote_port, AmStreamConnection::RTCP_CONN);
        conn->use_keys(static_cast<srtp_profile_t>(srtp_profile), local_key, remote_keys);
        addConnection(conn);
        return conn;
    } catch(string& error) {
        CLASS_ERROR("SRTCP connection error: %s", error.c_str());
    }

    return nullptr;
}

AmStreamConnection* AmMediaTransport::addZrtpConnection(const string& remote_address, int remote_port) {
    CLASS_DBG("addZrtpConnection state:%s, type:%s, raddr:%s, rport:%d",
              state2str().c_str(), type2str().c_str(), remote_address.c_str(), remote_port);

    AmZRTPConnection* conn = new AmZRTPConnection(this, remote_address, remote_port);
    addConnection(conn);
    return conn;
}

AmStreamConnection* AmMediaTransport::addRtpConnection(const string& remote_address, int remote_port)
{
    CLASS_DBG("addRtpConnection state:%s, type:%s, raddr:%s, rport:%d",
              state2str().c_str(), type2str().c_str(), remote_address.c_str(), remote_port);

    try {
        AmStreamConnection* conn = new AmRtpConnection(this, remote_address, remote_port);
        addConnection(conn);
        return conn;
    } catch(string& error) {
        CLASS_ERROR("RTP connection error: %s", error.c_str());
    }

    return nullptr;
}

AmStreamConnection* AmMediaTransport::addRtcpConnection(const string& remote_address, int remote_port)
{
    CLASS_DBG("addRtcpConnection state:%s, type:%s, raddr:%s, rport:%d",
              state2str().c_str(), type2str().c_str(), remote_address.c_str(), remote_port);

    try {
        AmStreamConnection* conn = new AmRtcpConnection(this, remote_address, remote_port);
        addConnection(conn);
        return conn;
    } catch(string& error) {
        CLASS_ERROR("RTCP connection error: %s", error.c_str());
    }

    return nullptr;
}

AmStreamConnection::ConnectionType AmMediaTransport::GetConnectionType(unsigned char* buf, unsigned int size)
{
    if(isStunMessage(buf, size))
        return AmStreamConnection::STUN_CONN;
    if(isDTLSMessage(buf, size))
        return AmStreamConnection::DTLS_CONN;
    if(isRTCPMessage(buf, size))
        return AmStreamConnection::RTCP_CONN;
    if(isRTPMessage(buf, size))
        return AmStreamConnection::RTP_CONN;
    if(isZRTPMessage(buf, size))
        return AmStreamConnection::ZRTP_CONN;

    return AmStreamConnection::UNKNOWN_CONN;
}

bool AmMediaTransport::isStunMessage(unsigned char* buf, unsigned int size)
{
    if(size < sizeof(unsigned short)) {
        return false;
    }

    // RFC 5764 5.1.2. Reception
    return *buf < 2;
}

bool AmMediaTransport::isDTLSMessage(unsigned char* buf, unsigned int size)
{
    if(!size) {
        return false;
    }

    // RFC 5764 5.1.2. Reception
    return *buf < 64 && *buf > 19;
}

bool AmMediaTransport::isRTCPMessage(unsigned char* buf, unsigned int size)
{
    if(size < sizeof(rtp_hdr_t)) {
        return false;
    }

    // RFC 5764 5.1.2. Reception
    if(*buf > 192 || *buf < 127)
        return false;

    rtp_hdr_t* rtp = reinterpret_cast<rtp_hdr_t*>(buf);
    if(IS_RTCP_PAYLOAD(rtp->pt)) {
        return true;
    }
    return false;
}

bool AmMediaTransport::isRTPMessage(unsigned char* buf, unsigned int size)
{
    if(size < sizeof(rtp_hdr_t)) {
        return false;
    }

    // RFC 5764 5.1.2. Reception
    if(*buf > 192 || *buf < 127)
        return false;

    // RFC 5764 5.1.2. Reception
    rtp_hdr_t* rtp = reinterpret_cast<rtp_hdr_t*>(buf);
    if(!IS_RTCP_PAYLOAD(rtp->pt)) {
        return true;
    }
    return false;
}

bool AmMediaTransport::isZRTPMessage(unsigned char* buf, unsigned int size)
{
    if(size < sizeof(rtp_hdr_t)) {
        return false;
    }

    // RFC 6189 5.0 ZRTP packet format
    if(*buf != 16 && *(((int*)buf) + 1) != ZRTP_MAGIC_COOKIE)
        return false;

    return true;
}

msg_sensor::packet_type_t AmMediaTransport::streamConnType2sensorPackType(AmStreamConnection::ConnectionType type)
{
    switch(type) {
        case AmStreamConnection::RTP_CONN:
            return msg_sensor::PTYPE_RTP;
        case AmStreamConnection::RTCP_CONN:
            return msg_sensor::PTYPE_RTCP;
        case AmStreamConnection::DTLS_CONN:
            return msg_sensor::PTYPE_DTLS;
        case AmStreamConnection::STUN_CONN:
            return msg_sensor::PTYPE_STUN;
        default:
            return msg_sensor::PTYPE_UNKNOWN;
    }
}

int AmMediaTransport::store_ice_cred(const SdpMedia& local_media, const SdpMedia& remote_media)
{
    ice_cred.luser = local_media.ice_ufrag;
    ice_cred.lpassword = local_media.ice_pwd;
    ice_cred.ruser = remote_media.ice_ufrag;
    ice_cred.rpassword = remote_media.ice_pwd;
    return 0;
}

int AmMediaTransport::store_srtp_cred(const SdpMedia& local_media, const SdpMedia& remote_media)
{
    int cprofile = getSrtpCredentialsBySdp(local_media, remote_media, srtp_cred.local_key, srtp_cred.remote_keys);
    if(cprofile < 0) return -1;
    srtp_cred.srtp_profile = static_cast<srtp_profile_t>(cprofile);
    return 0;
}

int AmMediaTransport::store_srtp_cred(int cptrofile, const string& local_key, const srtp_master_keys& remote_keys)
{
    srtp_cred.srtp_profile = static_cast<srtp_profile_t>(cptrofile);
    srtp_cred.local_key = local_key;
    srtp_cred.remote_keys = remote_keys;
    return 0;
}

string AmMediaTransport::state2str()
{
    switch(state) {
        case TRANSPORT_STATE_NONE:
            return "NONE";
        case TRANSPORT_STATE_ICE_INIT:
            return "ICE_INIT";
        case TRANSPORT_STATE_ICE_RESTART:
            return "ICE_RESTART";
        case TRANSPORT_STATE_ICE_SRTP:
            return "ICE_SRTP";
        case TRANSPORT_STATE_ICE_DTLS:
            return "ICE_DTLS";
        case TRANSPORT_STATE_ICE_RTP:
            return "ICE_RTP";
        case TRANSPORT_STATE_DTLS:
            return "DTLS";
        case TRANSPORT_STATE_RTP:
            return "RTP";
        case TRANSPORT_STATE_UDPTL:
            return "UDPTL";
        case TRANSPORT_STATE_RAW:
            return "RAW";
        case TRANSPORT_STATE_ZRTP:
            return "ZRTP";
    }
}

string AmMediaTransport::type2str()
{
    switch(type) {
        case RAW_TRANSPORT:
            return "RAW";
        case RTP_TRANSPORT:
            return "RTP";
        case RTCP_TRANSPORT:
            return "RTCP";
        case FAX_TRANSPORT:
            return "FAX";
        default:
            return "UNKNOWN";
    }
}

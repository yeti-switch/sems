#include "AmRtpTransport.h"
#include "AmFaxImage.h"
#include "AmRtpConnection.h"
#include "AmSrtpConnection.h"
#include "AmStunConnection.h"
#include "AmDtlsConnection.h"
#include "AmRtpReceiver.h"
#include "AmRtpPacket.h"
#include "AmSession.h"
#include "AmRtpStream.h"
#include "AmLcConfig.h"
#include "stuntypes.h"
#include "sip/raw_sender.h"
#include "botan/tls_magic.h"

#include <rtp/rtp.h>
#include <sys/ioctl.h>

#define RTCP_PAYLOAD_MIN 72
#define RTCP_PAYLOAD_MAX 76
#define IS_RTCP_PAYLOAD(p) ((p) >= RTCP_PAYLOAD_MIN && (p) <= RTCP_PAYLOAD_MAX)

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

AmRtpTransport::AmRtpTransport(AmRtpStream* _stream, int _if, int _proto_id)
    : seq(NONE)
    , mode(DEFAULT)
    , stream(_stream)
    , cur_rtp_conn(nullptr)
    , cur_rtcp_conn(nullptr)
    , cur_raw_conn(nullptr)
    , logger(nullptr)
    , sensor(nullptr)
    , type(RAW_TRANSPORT)
    , l_sd(0)
    , l_sd_ctx(-1)
    , l_port(0)
    , l_if(_if)
    , lproto_id(_proto_id)
    , srtp_enable(false)
    , dtls_enable(false)
{
    string local_ip;
    if(_proto_id >= 0) {
        local_ip = AmConfig.getMediaProtoInfo(l_if, _proto_id).local_ip;
    }

    if((local_ip[0] == '[') &&
      (local_ip[local_ip.size() - 1] == ']') ) {
        local_ip.pop_back();
        local_ip.erase(local_ip.begin());
    }

    CLASS_DBG("local_ip = %s\n",local_ip.c_str());

    if (!am_inet_pton(local_ip.c_str(), &l_saddr)) {
        throw string("AmRtpTransport: Invalid IP address: %s", local_ip.c_str());
    }

    recv_iov[0].iov_base = buffer;
    recv_iov[0].iov_len  = RTP_PACKET_BUF_SIZE;

    memset(&recv_msg,0,sizeof(recv_msg));

    recv_msg.msg_name       = &saddr;
    recv_msg.msg_namelen    = sizeof(struct sockaddr_storage);

    recv_msg.msg_iov        = recv_iov;
    recv_msg.msg_iovlen     = 1;

    recv_msg.msg_control    = recv_ctl_buf;
    recv_msg.msg_controllen = RTP_PACKET_TIMESTAMP_DATASIZE;

    RTP_info* rtpinfo = RTP_info::toMEDIA_RTP(&AmConfig.getMediaProtoInfo(_if, _proto_id));
    if(rtpinfo) {
        server_settings = rtpinfo->server_settings;
        client_settings = rtpinfo->client_settings;
        srtp_profiles = rtpinfo->profiles;
        srtp_enable = rtpinfo->srtp_enable && AmConfig.enable_srtp;
        dtls_enable = srtp_enable && rtpinfo->dtls_enable;
    }
}

AmRtpTransport::~AmRtpTransport()
{
    DBG("~AmRtpTransport[%p] l_sd = %d",to_void(this), l_sd);
    if(l_sd) {
        if(l_sd_ctx >= 0) {
            if (AmRtpReceiver::haveInstance()) {
                AmRtpReceiver::instance()->removeStream(l_sd,l_sd_ctx);
                l_sd_ctx = -1;
            }
        }
        AmConfig.media_ifs[l_if].proto_info[lproto_id]->freeRtpPort(l_port);
        close(l_sd);
    }

    for(auto conn : connections) {
        delete conn;
    }

    connections.clear();

    if (logger) dec_ref(logger);
    if (sensor) dec_ref(sensor);
}

void AmRtpTransport::setLogger(msg_logger* _logger)
{
    if (logger) dec_ref(logger);
        logger = _logger;
    if (logger) inc_ref(logger);
}

void AmRtpTransport::setSensor(msg_sensor *_sensor)
{
    if(sensor) dec_ref(sensor);
        sensor = _sensor;
    if(sensor) inc_ref(sensor);
}

void AmRtpTransport::setLocalPort(unsigned short p)
{
    l_port = p;
    am_set_port(&l_saddr,l_port);
}

void AmRtpTransport::setRAddr(const string& addr, unsigned short port)
{
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

void AmRtpTransport::setMode(Mode _mode)
{
    mode = _mode;
}

bool AmRtpTransport::isMute()
{
    bool ret = false;
    AmLock l(connections_mut);
    for(auto conn : connections) {
        if(conn->getConnType() == AmStreamConnection::RAW_CONN) {
            ret = conn->isMute();
            break;
        }
    }

    return ret;
}

string AmRtpTransport::getLocalIP()
{
    return AmConfig.getMediaProtoInfo(l_if, lproto_id).getIP();
}

void AmRtpTransport::getLocalAddr(struct sockaddr_storage* addr)
{
    memcpy(addr, &l_saddr, sizeof(sockaddr_storage));
}

int AmRtpTransport::getLocalPort()
{
    return l_port;
}

string AmRtpTransport::getRHost(bool rtcp)
{
    if(rtcp && cur_rtp_conn) return cur_rtp_conn->getRHost();
    else if(!rtcp && cur_rtcp_conn) return cur_rtcp_conn->getRHost();
    else if(cur_raw_conn) return cur_raw_conn->getRHost();
    return "";
}

int AmRtpTransport::getRPort(bool rtcp)
{
    if(rtcp && cur_rtp_conn) return cur_rtp_conn->getRPort();
    else if(!rtcp && cur_rtcp_conn) return cur_rtcp_conn->getRPort();
    else if(cur_raw_conn) return cur_raw_conn->getRPort();
    return 0;
}

void AmRtpTransport::getRAddr(bool rtcp, sockaddr_storage* addr)
{
    if(rtcp && cur_rtp_conn) return cur_rtp_conn->getRAddr(addr);
    else if(!rtcp && cur_rtcp_conn) return cur_rtcp_conn->getRAddr(addr);
    else getRAddr(addr);
}

void AmRtpTransport::getRAddr(sockaddr_storage* addr)
{
    if(cur_raw_conn) cur_raw_conn->getRAddr(addr);
}

int AmRtpTransport::hasLocalSocket()
{
    return l_sd;
}

int AmRtpTransport::getLocalSocket(bool reinit)
{
    CLASS_DBG("> getLocalSocket(%d)", reinit);

    if (l_sd && !reinit) {
        CLASS_DBG("< return existent l_sd:%d", l_sd);
        return l_sd;
    } else if(l_sd && reinit) {
        AmConfig.media_ifs[l_if].proto_info[lproto_id]->freeRtpPort(l_port);
        close(l_sd);
        l_sd = 0;
    }

    int sd=0;
    if((sd = socket(l_saddr.ss_family,SOCK_DGRAM,0)) == -1) {
        CLASS_ERROR("< %s\n",strerror(errno));
        throw string ("while creating new socket.");
    }
    SOCKET_LOG("[%p] socket(l_saddr.ss_family(%d),SOCK_DGRAM,0) = %d",
               to_void(this), l_saddr.ss_family,sd);

    int true_opt = 1;
    if(ioctl(sd, FIONBIO , &true_opt) == -1) {
        CLASS_ERROR("< %s\n",strerror(errno));
        close(sd);
        throw string ("while setting RTP socket non blocking.");
    }

    if(setsockopt(sd,SOL_SOCKET,SO_TIMESTAMP,
                  static_cast<void*>(&true_opt), sizeof(true_opt)) < 0)
    {
        CLASS_ERROR("< %s\n",strerror(errno));
        close(sd);
        throw string ("while setting RTP socket SO_TIMESTAMP opt");
    }

    if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR,
        static_cast<void*>(&true_opt), sizeof (true_opt)) == -1)
    {
        ERROR("%s\n",strerror(errno));
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

void AmRtpTransport::getSdpOffer(TransProt& transport, SdpMedia& offer)
{
    if(transport != TP_UDPTL && transport != TP_UDPTLSUDPTL)
        offer.type = MT_AUDIO;
    else
        offer.type = MT_IMAGE;

    if((transport == TP_RTPSAVP || transport == TP_RTPSAVPF) && !srtp_enable) {
        CLASS_WARN("srtp is disabled on related interface (%s). failover to RTPAVP profile",
                    AmConfig.getMediaIfaceInfo(l_if).name.c_str());
        offer.transport = TP_RTPAVP;
    } else if((transport == TP_UDPTLSRTPSAVP || transport == TP_UDPTLSRTPSAVPF) && !dtls_enable) {
        CLASS_WARN("dtls is disabled on related interface (%s). failover to RTPAVP profile",
                    AmConfig.getMediaIfaceInfo(l_if).name.c_str());
        offer.transport = TP_RTPAVP;
    } else if(transport == TP_RTPSAVP || transport == TP_RTPSAVPF) {
        for(auto profile : srtp_profiles) {
            SdpCrypto crypto;
            crypto.tag = 1;
            crypto.profile = profile;
            std::string key = AmSrtpConnection::gen_base64_key(static_cast<srtp_profile_t>(crypto.profile));
            if(key.empty()) {
                continue;
            }
            offer.crypto.push_back(crypto);
            offer.crypto.back().keys.push_back(SdpKeyInfo(key, 0, 1));
        }
    } else if(transport == TP_UDPTLSRTPSAVP || transport == TP_UDPTLSRTPSAVPF) {
        srtp_fingerprint_p fp = AmDtlsConnection::gen_fingerprint(&server_settings);
        offer.fingerprint.hash = fp.hash;
        offer.fingerprint.value = fp.value;
        offer.setup = S_ACTPASS;
    } else if(transport == TP_UDPTL) {
        t38_options_t options;
        options.getT38DefaultOptions();
        options.getAttributes(offer);
        offer.payloads.clear();
        offer.fmt = T38_FMT;
    } else if(transport == TP_UDPTLSUDPTL) {
        srtp_fingerprint_p fp = AmDtlsConnection::gen_fingerprint(&server_settings);
        offer.fingerprint.hash = fp.hash;
        offer.fingerprint.value = fp.value;
        offer.setup = S_ACTPASS;
        t38_options_t options;
        options.getT38DefaultOptions();
        options.getAttributes(offer);
        offer.payloads.clear();
        offer.fmt = T38_FMT;
    }
}

void AmRtpTransport::getSdpAnswer(const SdpMedia& offer, SdpMedia& answer)
{
    int transport = offer.transport;
    if(transport != TP_UDPTL && transport != TP_UDPTLSUDPTL)
        answer.type = MT_AUDIO;
    else
        answer.type = MT_IMAGE;

    if((offer.is_simple_srtp() && !srtp_enable) ||
       (offer.is_dtls_srtp() && !dtls_enable)) {
        throw AmSession::Exception(488,"transport not supported");
    } else if(transport == TP_RTPSAVP || transport == TP_RTPSAVPF) {
        if(offer.crypto.empty()) {
            throw AmSession::Exception(488,"absent crypto attribute");
        }
        answer.crypto.push_back(offer.crypto[0]);
        answer.crypto.back().keys.clear();
        for(auto profile : srtp_profiles) {
            if(profile == answer.crypto[0].profile) {
                answer.crypto.back().keys.push_back(SdpKeyInfo(AmSrtpConnection::gen_base64_key(
                    static_cast<srtp_profile_t>(answer.crypto[0].profile)), 0, 1));
            }
        }
        if(answer.crypto.back().keys.empty()) {
            throw AmSession::Exception(488,"no compatible srtp profile");
        }
    } else if(transport == TP_UDPTLSRTPSAVP || transport == TP_UDPTLSRTPSAVPF) {
        dtls_settings* settings = (offer.setup == S_ACTIVE) ?
                                                    static_cast<dtls_settings*>(&server_settings) :
                                                    static_cast<dtls_settings*>(&client_settings);
        srtp_fingerprint_p fp = AmDtlsConnection::gen_fingerprint(settings);
        answer.fingerprint.hash = fp.hash;
        answer.fingerprint.value = fp.value;
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
                                                    static_cast<dtls_settings*>(&server_settings) :
                                                    static_cast<dtls_settings*>(&client_settings);
        srtp_fingerprint_p fp = AmDtlsConnection::gen_fingerprint(settings);
        answer.fingerprint.hash = fp.hash;
        answer.fingerprint.value = fp.value;
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
    }
}

void AmRtpTransport::getIceCandidate(SdpMedia& media)
{
    SdpIceCandidate candidate;
    candidate.conn.network = NT_IN;
    candidate.comp_id = type;
    candidate.conn.addrType = (l_saddr.ss_family == AF_INET) ? AT_V4 : AT_V6;
    candidate.conn.address = am_inet_ntop(&l_saddr) + " " + int2str(l_port);
    media.ice_candidate.push_back(candidate);
}

void AmRtpTransport::initIceConnection(const SdpMedia& local_media, const SdpMedia& remote_media)
{
    CLASS_DBG("[%p]AmRtpTransport::initIceConnection seq - %d", to_void(stream), seq);
    if(seq == NONE) {
        seq = ICE;
        string local_key, remote_key;
        int cprofile = 0;
        if(local_media.is_simple_srtp() && srtp_enable) {
            cprofile = getSrtpCredentialsBySdp(local_media, remote_media, local_key, remote_key);
        }
        for(auto candidate : remote_media.ice_candidate) {
            if(candidate.transport == ICTR_UDP) {
                string addr = candidate.conn.address;
                vector<string> addr_port = explode(addr, " ");
                sockaddr_storage sa;
                sa.ss_family = (candidate.conn.addrType == AT_V4) ? AF_INET : AF_INET6;
                if(addr_port.size() != 2) continue;
                string address = addr_port[0];
                int port = 0;
                str2int(addr_port[1], port);

                if(type == candidate.comp_id && sa.ss_family == l_saddr.ss_family) {
                    try {
                        AmStunConnection* conn = new AmStunConnection(this, address, port, candidate.priority);
                        conn->set_credentials(local_media.ice_ufrag, local_media.ice_pwd, remote_media.ice_ufrag, remote_media.ice_pwd);
                        addConnection(conn);
                        conn->send_request();
                    } catch(string& error) {
                        CLASS_ERROR("Can't add ice candidate address. error - %s", error.c_str());
                    }

                    if(local_media.is_simple_srtp() && srtp_enable) {
                         addSrtpConnection(address, port, cprofile, local_key, remote_key);
                    } else if(local_media.is_dtls_srtp() && AmConfig.enable_srtp) {
                        srtp_fingerprint_p fingerprint(remote_media.fingerprint.hash, remote_media.fingerprint.value);
                        try {
                            if(local_media.setup == S_ACTIVE || remote_media.setup == S_PASSIVE) {
                                addConnection(new AmDtlsConnection(this, address, port, fingerprint, true));
                            } else if(local_media.setup == S_PASSIVE || remote_media.setup == S_ACTIVE) {
                                addConnection(new AmDtlsConnection(this, address, port, fingerprint, false));
                            }
                        } catch(string& error) {
                            CLASS_ERROR("Can't add dtls connection. error - %s", error.c_str());
                        }
                    } else {
                         addRtpConnection(address, port);
                    }
                }
            }
        }
    }
}

void AmRtpTransport::initRtpConnection(const string& remote_address, int remote_port)
{
    CLASS_DBG("[%p]AmRtpTransport::initRtpConnection seq - %d", to_void(stream), seq);
    if(seq == NONE) {
        seq = RTP;
        addRtpConnection(remote_address, remote_port);
    }
}

void AmRtpTransport::initSrtpConnection(const string& remote_address, int remote_port, const SdpMedia& local_media, const SdpMedia& remote_media)
{
    if(!srtp_enable) return;
    
    CLASS_DBG("[%p]AmRtpTransport::initSrtpConnection seq - %d", to_void(stream), seq);
    if(seq == NONE ||
       seq == ICE) {
        seq = RTP;

        string local_key, remote_key;
        int cprofile = getSrtpCredentialsBySdp(local_media, remote_media, local_key, remote_key);
        if(cprofile < 0)
            return;

        addSrtpConnection(remote_address, remote_port, cprofile, local_key, remote_key);
    }
}

void AmRtpTransport::initSrtpConnection(uint16_t srtp_profile, const string& local_key, const string& remote_key)
{
    if(!srtp_enable) return;

    CLASS_DBG("[%p]AmRtpTransport::initSrtpConnection seq - %d", to_void(stream), seq);
    vector<sockaddr_storage> addrs;
    {
        AmLock l(connections_mut);
        for(auto conn : connections) {
            if(seq == ICE){
                if(conn->getConnType() == AmStreamConnection::STUN_CONN) {
                    sockaddr_storage raddr;
                    conn->getRAddr(&raddr);
                    addrs.push_back(raddr);
                }
            } else if(seq == DTLS) {
                if(conn->getConnType() == AmStreamConnection::DTLS_CONN) {
                    sockaddr_storage raddr;
                    conn->getRAddr(&raddr);
                    addrs.push_back(raddr);
                }
            }
        }
    }

    for(auto addr : addrs) {
        addSrtpConnection(am_inet_ntop(&addr), am_get_port(&addr), srtp_profile, local_key, remote_key);
    }

    seq = RTP;
}

void AmRtpTransport::initDtlsConnection(const string& remote_address, int remote_port, const SdpMedia& local_media, const SdpMedia& remote_media)
{
    if(!dtls_enable) return;

    CLASS_DBG("[%p]AmRtpTransport::initDtlsConnection seq - %d", to_void(stream), seq);
    if(seq == NONE) {
        seq = DTLS;
        srtp_fingerprint_p fingerprint(remote_media.fingerprint.hash, remote_media.fingerprint.value);
        try {
            if(local_media.setup == S_ACTIVE || remote_media.setup == S_PASSIVE) {
                addConnection(new AmDtlsConnection(this, remote_address, remote_port, fingerprint, true));
            } else if(local_media.setup == S_PASSIVE || remote_media.setup == S_ACTIVE) {
                addConnection(new AmDtlsConnection(this, remote_address, remote_port, fingerprint, false));
            }
        } catch(string& error) {
            CLASS_ERROR("Can't add dtls connection. error - %s", error.c_str());
        }
    }
}

void AmRtpTransport::initUdptlConnection(const string& remote_address, int remote_port)
{
    if(seq == NONE || seq == RTP) {
        seq = UDPTL;
        addConnection(new UDPTLConnection(this, remote_address, remote_port));
        mode = FAX;
    } else if(seq == DTLS) {
        seq = UDPTL;
        {
        AmLock l(connections_mut);
            for(auto &conn : connections) {
                if(conn->getConnType() == AmStreamConnection::DTLS_CONN) {
                    connections.push_back(new DTLSUDPTLConnection(this, remote_address, remote_port, conn));
                }
            }
        }
        mode = DTLS_FAX;
    }
}

void AmRtpTransport::addConnection(AmStreamConnection* conn)
{
    AmLock l(connections_mut);
    connections.push_back(conn);
}

void AmRtpTransport::removeConnection(AmStreamConnection* conn)
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

void AmRtpTransport::allowStunConnection(sockaddr_storage* remote_addr, int priority)
{
    (void)remote_addr;
    //TODO(alexey.v): set current connections by candidate priority
    stream->allowStunConnection(this, priority);
}

void AmRtpTransport::dtlsSessionActivated(uint16_t srtp_profile, const vector<uint8_t>& local_key, const vector<uint8_t>& remote_key)
{
    stream->dtlsSessionActivated(this, srtp_profile, local_key, remote_key);
}

void AmRtpTransport::onRtpPacket(AmRtpPacket* packet, AmStreamConnection* conn)
{
    if(!cur_rtp_conn)
        cur_rtp_conn = conn;
    stream->onRtpPacket(packet, this);
}

void AmRtpTransport::onRtcpPacket(AmRtpPacket* packet, AmStreamConnection* conn)
{
    if(!cur_rtcp_conn)
        cur_rtcp_conn = conn;
    stream->onRtcpPacket(packet, this);
}

void AmRtpTransport::onRawPacket(AmRtpPacket* packet, AmStreamConnection* conn)
{
    if(mode == DEFAULT) {
        onPacket(packet->getBuffer(), packet->getBufferSize(), packet->saddr, packet->recv_time);
        stream->freeRtpPacket(packet);
    } else if(mode == FAX || mode == DTLS_FAX) {
        cur_raw_conn = conn;
        stream->onUdptlPacket(packet, this);
    } else {
        cur_raw_conn = conn;
        stream->onRawPacket(packet, this);
    }
}

void AmRtpTransport::updateStunTimers()
{
    for(auto conn : connections) {
        if(conn->getConnType() == AmStreamConnection::STUN_CONN)
            static_cast<AmStunConnection*>(conn)->updateStunTimer();
    }
}

void AmRtpTransport::stopReceiving()
{
    AmLock l(stream_mut);
    CLASS_DBG("stopReceiving() l_sd:%d, seq:%d", l_sd, seq);
    if(hasLocalSocket() && seq != NONE) {
        CLASS_DBG("[%p]remove %s stream from RTP receiver\n",
            to_void(stream),  transport_type2str(getTransportType()));
        AmRtpReceiver::instance()->removeStream(getLocalSocket(),l_sd_ctx);
        l_sd_ctx = -1;
    }
}

void AmRtpTransport::resumeReceiving()
{
    AmLock l(stream_mut);
    CLASS_DBG("resumeReceiving() l_sd:%d, seq:%d", l_sd, seq);
    if(hasLocalSocket() && seq != NONE) {
        CLASS_DBG("[%p]add/resume %s stream into RTP receiver\n",
            to_void(stream),  transport_type2str(getTransportType()));
        l_sd_ctx = AmRtpReceiver::instance()->addStream(l_sd, this, l_sd_ctx);
        if(l_sd_ctx < 0) {
            CLASS_DBG("error on add/resuming stream. l_sd_ctx = %d", l_sd_ctx);
        }
    }
}

void AmRtpTransport::setPassiveMode(bool p)
{
    AmLock l(connections_mut);
    for(auto conn : connections) {
        conn->setPassiveMode(p);
    }
}

void AmRtpTransport::log_rcvd_packet(const char *buffer, int len, struct sockaddr_storage &recv_addr, AmStreamConnection::ConnectionType type)
{
    static const cstring empty;
    if (logger)
        logger->log(buffer, len, &recv_addr, &l_saddr, empty);
    if (sensor)
        sensor->feed(buffer, static_cast<int>(b_size), &saddr, &l_saddr, streamConnType2sensorPackType(type));
}

void AmRtpTransport::log_sent_packet(const char *buffer, int len, struct sockaddr_storage &send_addr, AmStreamConnection::ConnectionType type)
{
    static const cstring empty;
    if (logger)
        logger->log(buffer, len, &l_saddr, &send_addr, empty);
    if (sensor)
        sensor->feed(buffer, static_cast<int>(b_size), &l_saddr, &send_addr, streamConnType2sensorPackType(type));
}

ssize_t AmRtpTransport::send(AmRtpPacket* packet, AmStreamConnection::ConnectionType type)
{
    AmStreamConnection* cur_stream = nullptr;
    if(type == AmStreamConnection::RTP_CONN) {
        cur_stream = cur_rtp_conn;
    } else if(type == AmStreamConnection::RTCP_CONN) {
        cur_stream = cur_rtcp_conn;
    } else if(type == AmStreamConnection::RAW_CONN) {
        cur_stream = cur_raw_conn;
    }
    
    ssize_t ret = 0;
    if(cur_stream) {
        ret = cur_stream->send(packet);
    } else {
        AmLock l(connections_mut);
        for(auto conn : connections) {
            sockaddr_storage addr;
            packet->getAddr(&addr);
            if(conn->isUseConnection(type)) {
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

ssize_t AmRtpTransport::send(sockaddr_storage* raddr, unsigned char* buf, int size, AmStreamConnection::ConnectionType type)
{
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
        ERROR("while sending packet with sendto(%d,%p,%d,0,%p,%ld): %s\n",
            l_sd,
            static_cast<void *>(buf),size,
            static_cast<void *>(raddr),SA_len(raddr),
            strerror(errno));
        log_stacktrace(L_DBG);
        return -1;
    }
    return err;
}

int AmRtpTransport::sendmsg(unsigned char* buf, int size)
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
        ERROR("sendto: %s\n",strerror(errno));
        return -1;
    }

    return 0;
}

ssize_t AmRtpTransport::recv(int sd)
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

void AmRtpTransport::recvPacket(int fd)
{
    if(recv(fd) > 0) {
        onPacket(buffer, b_size, saddr, recv_time);
    }
}

void AmRtpTransport::onPacket(unsigned char* buf, unsigned int size, sockaddr_storage& addr, struct timeval recvtime)
{
    AmStreamConnection::ConnectionType ctype;
    if(mode == DEFAULT) {
        ctype = GetConnectionType(buf, size);
        if(ctype == AmStreamConnection::UNKNOWN_CONN) {
            CLASS_WARN("Unknown packet type from %s:%d, ignore it",
                       am_inet_ntop(&addr).c_str(),
                       am_get_port(&addr));
            return;
        }
    } else if(mode == FAX){
        ctype = AmStreamConnection::UDPTL_CONN;
    } else if(mode == DTLS_FAX) {
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

        if(!s_conn && !conns_by_type.empty()) {
            s_conn = conns_by_type[0];
        }
    }

    if(!s_conn) {
        return;
    }

    s_conn->handleConnection(buf, size, &addr, recvtime);
}

int AmRtpTransport::getSrtpCredentialsBySdp(const SdpMedia& local_media, const SdpMedia& remote_media, string& l_key, string& r_key)
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
    for(auto key : local_media.crypto) {
        if(cprofile == key.profile) {
            if(key.keys.empty()) {
                CLASS_ERROR("local secure audio stream without master key");
                return -1;
            }
            AmSrtpConnection::base64_key(key.keys[0].key, local_key, local_key_size);
            break;
        }
    }
    for(auto key : remote_media.crypto) {
        if(cprofile == key.profile) {
            if(key.keys.empty()) {
                CLASS_ERROR("local secure audio stream without master key");
                return -1;
            }

            AmSrtpConnection::base64_key(key.keys[0].key, remote_key, remote_key_size);
            break;
        }
    }

    l_key.assign(reinterpret_cast<char *>(local_key), local_key_size);
    r_key.assign(reinterpret_cast<char *>(remote_key), remote_key_size);

    return cprofile;
}

void AmRtpTransport::addSrtpConnection(const string& remote_address, int remote_port,
                                       int srtp_profile, const string& local_key, const string& remote_key)
{
    if(type == RTP_TRANSPORT) {
        try {
            AmSrtpConnection* conn = new AmSrtpConnection(this, remote_address, remote_port, AmStreamConnection::RTP_CONN);
            conn->use_key(static_cast<srtp_profile_t>(srtp_profile),
                          reinterpret_cast<const unsigned char*>(local_key.data()), local_key.size(),
                          reinterpret_cast<const unsigned char*>(remote_key.data()), remote_key.size());
            addConnection(conn);
            if(conn->isMute()) {
                stream->mute = true;
            }
        } catch(string& error) {
            CLASS_ERROR("Can't add srtp connection. error - %s", error.c_str());
        }
    }
    try {
        AmSrtpConnection* conn = new AmSrtpConnection(this, remote_address, remote_port, AmStreamConnection::RTCP_CONN);
        conn->use_key(static_cast<srtp_profile_t>(srtp_profile),
                      reinterpret_cast<const unsigned char*>(local_key.data()), local_key.size(),
                      reinterpret_cast<const unsigned char*>(remote_key.data()), remote_key.size());
        addConnection(conn);
    } catch(string& error) {
        CLASS_ERROR("Can't add srtcp connection. error - %s", error.c_str());
    }
}

void AmRtpTransport::addRtpConnection(const string& remote_address, int remote_port)
{
    AmStreamConnection* conn = nullptr;
    if(type == RTP_TRANSPORT) {
        try {
            conn = new AmRtpConnection(this, remote_address, remote_port);
            addConnection(conn);
            if(conn->isMute()) {
                stream->mute = true;
            }
        } catch(string& error) {
            CLASS_ERROR("Can't add rtp connection. error - %s", error.c_str());
        }
    }

    try {
        conn = new AmRtcpConnection(this, remote_address, remote_port);
        addConnection(conn);
    } catch(string& error) {
        CLASS_ERROR("Can't add rtcp connection. error - %s", error.c_str());
    }
}

AmStreamConnection::ConnectionType AmRtpTransport::GetConnectionType(unsigned char* buf, unsigned int size)
{
    if(isStunMessage(buf, size))
        return AmStreamConnection::STUN_CONN;
    if(isDTLSMessage(buf, size))
        return AmStreamConnection::DTLS_CONN;
    if(isRTCPMessage(buf, size))
        return AmStreamConnection::RTCP_CONN;
    if(isRTPMessage(buf, size))
        return AmStreamConnection::RTP_CONN;

    return AmStreamConnection::UNKNOWN_CONN;
}

bool AmRtpTransport::isStunMessage(unsigned char* buf, unsigned int size)
{
    if(size < sizeof(unsigned short)) {
        return false;
    }

    // RFC 5764 5.1.2. Reception
    return *buf < 2;
}

bool AmRtpTransport::isDTLSMessage(unsigned char* buf, unsigned int size)
{
    if(!size) {
        return false;
    }

    // RFC 5764 5.1.2. Reception
    return *buf < 64 && *buf > 19;
}

bool AmRtpTransport::isRTCPMessage(unsigned char* buf, unsigned int size)
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

bool AmRtpTransport::isRTPMessage(unsigned char* buf, unsigned int size)
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


msg_sensor::packet_type_t AmRtpTransport::streamConnType2sensorPackType(AmStreamConnection::ConnectionType type)
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

#include "AmRtpTransport.h"
#include "AmRtpConnection.h"
#include "AmSrtpConnection.h"
#include "AmRtpReceiver.h"
#include "AmRtpPacket.h"
#include "AmRtpStream.h"
#include "AmLcConfig.h"
#include "stuntypes.h"
#include "sip/raw_sender.h"
#include "botan/tls_magic.h"

#include <rtp/rtp.h>
#include <sys/ioctl.h>
#include "AmStunConnection.h"
#include "AmDtlsConnection.h"

#define RTCP_PAYLOAD_MIN 72
#define RTCP_PAYLOAD_MAX 76
#define IS_RTCP_PAYLOAD(p) ((p) >= RTCP_PAYLOAD_MIN && (p) <= RTCP_PAYLOAD_MAX)

AmRtpTransport::AmRtpTransport(AmRtpStream* _stream, int _if, int _proto_id, int tr_type)
    : stream(_stream)
    , cur_rtp_stream(0)
    , cur_rtcp_stream(0)
    , cur_raw_stream(0)
    , l_if(_if)
    , lproto_id(_proto_id)
    , l_port(0)
    , l_sd(0)
    , l_sd_ctx(-1)
    , logger(0)
    , sensor(0)
    , type(tr_type)
    , seq(NONE)
{
    string local_ip;
    if(_proto_id >= 0) {
        local_ip = AmConfig.media_ifs[l_if].proto_info[_proto_id]->local_ip;
    }

    if((local_ip[0] == '[') &&
      (local_ip[local_ip.size() - 1] == ']') ) {
        local_ip.pop_back();
        local_ip.erase(local_ip.begin());
    }

    CLASS_DBG("local_ip = %s\n",local_ip.c_str());

    if (!am_inet_pton(local_ip.c_str(), &l_saddr)) {
        throw string("AmRtpTransport: Invalid IP address: %s", local_ip.c_str());
        return;
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
}

AmRtpTransport::~AmRtpTransport()
{
    for(auto conn : connections) {
        delete conn;
    }

    connections.clear();

    if(l_sd) {
        if (AmRtpReceiver::haveInstance()) {
            AmRtpReceiver::instance()->removeStream(l_sd,l_sd_ctx);
            l_sd_ctx = -1;
        }
        close(l_sd);
    }

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
    for(auto conn : connections) {
        if(conn->getConnType() == AmStreamConnection::RAW_CONN) {
            conn->setRAddr(addr, port);
            return;
        }
    }

    connections.push_back(new AmRawConnection(this, addr, port));
    cur_raw_stream = connections.back();
}

bool AmRtpTransport::isMute()
{
    for(auto conn : connections) {
        if(conn->getConnType() == AmStreamConnection::RAW_CONN) {
            return conn->isMute();
        }
    }

    return false;
}

string AmRtpTransport::getLocalIP()
{
    return AmConfig.media_ifs[l_if].proto_info[lproto_id]->getIP();
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
    for(auto conn : connections) {
        if(rtcp && conn->getConnType() == AmStreamConnection::RTCP_CONN) {
            return conn->getRHost();
        } else if(!rtcp && conn->getConnType() == AmStreamConnection::RTCP_CONN) {
            return conn->getRHost();
        }
    }

    return "";
}

int AmRtpTransport::getRPort(bool rtcp)
{
    for(auto conn : connections) {
        if(rtcp && conn->getConnType() == AmStreamConnection::RTCP_CONN) {
            return conn->getRPort();
        } else if(!rtcp && conn->getConnType() == AmStreamConnection::RTCP_CONN) {
            return conn->getRPort();
        }
    }

    return 0;
}

void AmRtpTransport::getRAddr(bool rtcp, sockaddr_storage* addr)
{
    for(auto conn : connections) {
        if(rtcp && conn->getConnType() == AmStreamConnection::RTCP_CONN) {
            conn->getRAddr(addr);
        } else if(!rtcp && conn->getConnType() == AmStreamConnection::RTP_CONN) {
            conn->getRAddr(addr);
        }
    }
}

void AmRtpTransport::getRAddr(sockaddr_storage* addr)
{
    for(auto conn : connections) {
        if(conn->getConnType() == AmStreamConnection::RAW_CONN) {
            conn->getRAddr(addr);
        }
    }
}

int AmRtpTransport::hasLocalSocket()
{
    return l_sd;
}

int AmRtpTransport::getLocalSocket(bool reinit)
{
    if (l_sd && !reinit)
        return l_sd;
    else if(l_sd && reinit) {
        close(l_sd);
        l_sd = 0;
    }

    int sd=0;
    if((sd = socket(l_saddr.ss_family,SOCK_DGRAM,0)) == -1) {
        CLASS_ERROR("%s\n",strerror(errno));
        throw string ("while creating new socket.");
    }

    int true_opt = 1;
    if(ioctl(sd, FIONBIO , &true_opt) == -1) {
        CLASS_ERROR("%s\n",strerror(errno));
        close(sd);
        throw string ("while setting RTP socket non blocking.");
    }

    if(setsockopt(sd,SOL_SOCKET,SO_TIMESTAMP,
                  (void*)&true_opt, sizeof(true_opt)) < 0)
    {
        CLASS_ERROR("%s\n",strerror(errno));
        close(sd);
        throw string ("while setting RTP socket SO_TIMESTAMP opt");
    }

    l_sd = sd;

    return l_sd;
}

void AmRtpTransport::setSocketOption()
{
    int true_opt = 1;
    if(setsockopt(l_sd, SOL_SOCKET, SO_REUSEADDR,
        (void*)&true_opt, sizeof (true_opt)) == -1)
    {
        ERROR("%s\n",strerror(errno));
        close(l_sd);
        l_sd = 0;
        throw string ("while setting local address reusable.");
    }

    int tos = AmConfig.media_ifs[l_if].proto_info[lproto_id]->tos_byte;
    if(tos &&
        setsockopt(l_sd, IPPROTO_IP, IP_TOS,  &tos, sizeof(tos)) == -1)
    {
        CLASS_WARN("failed to set IP_TOS for descriptors %d",l_sd);
    }

}

void AmRtpTransport::addToReceiver()
{
    l_sd_ctx = AmRtpReceiver::instance()->addStream(l_sd, this,l_sd_ctx);
    if(l_sd_ctx < 0) {
        CLASS_ERROR("can't add to RTP receiver (%s:%i)\n",
            get_addr_str((sockaddr_storage*)&l_saddr).c_str(),l_port);
    }
}

void AmRtpTransport::initIceConnection(const SdpMedia& local_media, const SdpMedia& remote_media)
{
    if(seq == NONE) {
        seq = ICE;
        for(auto candidate : remote_media.ice_candidate) {
            if(candidate.transport == ICTR_UDP) {
                string addr = candidate.conn.address;
                vector<string> addr_port = explode(addr, " ");
                sockaddr_storage sa = {0};
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
                        addConnection(new AmRtpConnection(this, address, port));
                        addConnection(new AmRtcpConnection(this, address, port));
                    } catch(string& error) {
                        CLASS_ERROR("Can't add ice candidate address. error - %s", error.c_str());
                    }
                }
            }
        }
    }
}

void AmRtpTransport::initRtpConnection(const string& remote_address, int remote_port)
{
    CLASS_DBG("[%p]AmRtpTransport::initRtpConnection seq - %d, connections size - %zu", stream, seq, connections.size());
    if(seq == NONE) {
        seq = RTP;
        AmStreamConnection* conn = 0;
        if(type != RTCP_TRANSPORT) {
            try {
                conn = new AmRtpConnection(this, remote_address, remote_port);
                addConnection(conn);
                cur_rtp_stream = conn;
                if(conn->isMute()) {
                    stream->mute = true;
                }
            } catch(string& error) {
                CLASS_ERROR("Can't add rtp connection. error - %s", error.c_str());
            }
        }
    }
}

void AmRtpTransport::initRtcpConnection(const string& remote_address, int remote_port)
{
    CLASS_DBG("[%p]AmRtpTransport::initRtcpConnection seq - %d", stream, seq);
    if(seq == NONE) {
        try {
            seq = RTP;
            AmStreamConnection* conn = new AmRtcpConnection(this, remote_address, remote_port);
            addConnection(conn);
            cur_rtcp_stream = conn;
        } catch(string& error) {
            CLASS_ERROR("Can't add rtcp connection. error - %s", error.c_str());
        }
    }
}

void AmRtpTransport::initSrtpConnection(const string& remote_address, int remote_port, const SdpMedia& local_media, const SdpMedia& remote_media)
{
    if(seq == NONE) {
        seq = RTP;
        CryptoProfile cprofile = CP_NONE;
        if(local_media.crypto.size() == 1) {
            cprofile = local_media.crypto[0].profile;
        } else if(remote_media.crypto.size() == 1) {
            cprofile = remote_media.crypto[0].profile;
        } else if(local_media.crypto.empty()){
            CLASS_ERROR("local secure audio stream without encryption details");
            return;
        } else if(remote_media.crypto.empty()){
            CLASS_ERROR("remote secure audio stream without encryption details");
            return;
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
                    return;
                }
                AmSrtpConnection::base64_key(key.keys[0].key, local_key, local_key_size);
                break;
            }
        }
        for(auto key : remote_media.crypto) {
            if(cprofile == key.profile) {
                if(key.keys.empty()) {
                    CLASS_ERROR("local secure audio stream without master key");
                    return;
                }

                AmSrtpConnection::base64_key(key.keys[0].key, remote_key, remote_key_size);
                break;
            }
        }

        if(type == RTP_TRANSPORT) {
            try {
                AmSrtpConnection* conn = new AmSrtpConnection(this, remote_address, remote_port, AmStreamConnection::RTP_CONN);
                conn->use_key((srtp_profile_t)cprofile, local_key, local_key_size, remote_key, remote_key_size);
                addConnection(conn);
                if(conn->isMute()) {
                    stream->mute = true;
                }
                cur_rtp_stream = conn;
            } catch(string& error) {
                CLASS_ERROR("Can't add srtp connection. error - %s", error.c_str());
            }
        }
        try {
            AmSrtpConnection* conn = new AmSrtpConnection(this, remote_address, remote_port, AmStreamConnection::RTCP_CONN);
            conn->use_key((srtp_profile_t)cprofile, local_key, local_key_size, remote_key, remote_key_size);
            addConnection(conn);
            cur_rtcp_stream = conn;
        } catch(string& error) {
            CLASS_ERROR("Can't add srtcp connection. error - %s", error.c_str());
        }
    }
}

void AmRtpTransport::initDtlsConnection(const std::__cxx11::string& remote_address, int remote_port, const SdpMedia& local_media, const SdpMedia& remote_media)
{
    if(seq == NONE) {
        seq = DTLS;
        try {
            srtp_fingerprint_p fingerprint(remote_media.fingerprint.hash, remote_media.fingerprint.value);
            if(local_media.setup == SdpMedia::SetupActive || remote_media.setup == SdpMedia::SetupPassive) {
                addConnection(new AmDtlsConnection(this, remote_address, remote_port, fingerprint, true));
            } else if(local_media.setup == SdpMedia::SetupPassive || remote_media.setup == SdpMedia::SetupActive) {
                addConnection(new AmDtlsConnection(this, remote_address, remote_port, fingerprint, false));
            }
        } catch(string& error) {
            CLASS_ERROR("Can't add dtls connection. error - %s", error.c_str());
        }
    }
}

void AmRtpTransport::addConnection(AmStreamConnection* conn)
{
    connections.push_back(conn);
}

void AmRtpTransport::removeConnection(AmStreamConnection* conn)
{
    for(auto conn_it = connections.begin(); conn_it != connections.end(); conn_it++) {
        if(*conn_it == conn) {
            connections.erase(conn_it);
            delete conn;
            break;
        }
    }
}

void AmRtpTransport::allowStunConnection(sockaddr_storage* remote_addr)
{
}

void AmRtpTransport::dtlsSessionActivated(uint16_t srtp_profile, const vector<uint8_t>& local_key, const vector<uint8_t>& remote_key)
{
}

void AmRtpTransport::stopReceiving()
{
    if(hasLocalSocket())
        AmRtpReceiver::instance()->removeStream(getLocalSocket(),l_sd_ctx);
}

void AmRtpTransport::resumeReceiving()
{
    if(hasLocalSocket()){
        l_sd_ctx = AmRtpReceiver::instance()->addStream(l_sd, this, l_sd_ctx);
        if(l_sd_ctx < 0) {
            ERROR("error on add/resuming stream. l_sd_ctx = %d", l_sd_ctx);
        }
    } else {
        ERROR("error on add/resuming stream. socket not created");
    }
}

void AmRtpTransport::setPassiveMode(bool p)
{
    for(auto conn : connections) {
        if (conn->getConnType() == AmStreamConnection::RTP_CONN ||
            conn->getConnType() == AmStreamConnection::RTCP_CONN) {
            conn->setPassiveMode(p);
        }
    }
}

bool AmRtpTransport::getPassiveMode()
{
    for(auto conn : connections) {
        if(conn->getConnType() == AmStreamConnection::RTP_CONN) {
            return conn->getPassiveMode();
        }
    }

    return false;
}

void AmRtpTransport::log_rcvd_packet(const char *buffer, int len, struct sockaddr_storage &recv_addr, AmStreamConnection::ConnectionType type)
{
    static const cstring empty;
    if (logger)
        logger->log((const char *)buffer, len, &recv_addr, &l_saddr, empty);
    if (sensor)
        sensor->feed((const char *)buffer, b_size, &saddr, &l_saddr, streamConnType2sensorPackType(type));
}

void AmRtpTransport::log_sent_packet(const char *buffer, int len, struct sockaddr_storage &send_addr, AmStreamConnection::ConnectionType type)
{
    static const cstring empty;
    if (logger)
        logger->log((const char *)buffer, len, &l_saddr, &send_addr, empty);
    if (sensor)
        sensor->feed((const char *)buffer, b_size, &l_saddr, &send_addr, streamConnType2sensorPackType(type));
}

int AmRtpTransport::send(AmRtpPacket* packet, AmStreamConnection::ConnectionType type)
{
    AmStreamConnection* cur_stream = 0;
    if(type == AmStreamConnection::RTP_CONN) {
        cur_stream = cur_rtp_stream;
    } else if(type == AmStreamConnection::RTCP_CONN) {
        cur_stream = cur_rtcp_stream;
    } else if(type == AmStreamConnection::RAW_CONN) {
        cur_stream = cur_raw_stream;
    }
    
    if(cur_stream) {
        return cur_stream->send(packet);
    }
    
    return 0;
}

int AmRtpTransport::send(sockaddr_storage* raddr, unsigned char* buf, int size, AmStreamConnection::ConnectionType type)
{
    log_sent_packet((char*)buf, size, *raddr, type);

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
    return 0;
}

int AmRtpTransport::sendmsg(unsigned char* buf, int size)
{
    MEDIA_info* iface = AmConfig.media_ifs[l_if].proto_info[lproto_id];
    unsigned int sys_if_idx = iface->net_if_idx;

    struct msghdr hdr;
    struct cmsghdr* cmsg;

    union {
        char cmsg4_buf[CMSG_SPACE(sizeof(struct in_pktinfo))];
        char cmsg6_buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    } cmsg_buf;

    struct iovec msg_iov[1];
    msg_iov[0].iov_base = (void*)buf;
    msg_iov[0].iov_len  = size;

    bzero(&hdr,sizeof(hdr));
    hdr.msg_name = (void*)&l_saddr;
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

        struct in_pktinfo* pktinfo = (struct in_pktinfo*) CMSG_DATA(cmsg);
        pktinfo->ipi_ifindex = sys_if_idx;
    }
    else if(l_saddr.ss_family == AF_INET6) {
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

        struct in6_pktinfo* pktinfo = (struct in6_pktinfo*) CMSG_DATA(cmsg);
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

int AmRtpTransport::recv(int sd)
{
    cmsghdr *cmsgptr;
    int ret = recvmsg(sd,&recv_msg,0);

    for (cmsgptr = CMSG_FIRSTHDR(&recv_msg);
        cmsgptr != NULL;
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
        b_size = ret;
    }

    return ret;
}

void AmRtpTransport::recvPacket(int fd)
{
    if(recv(fd) > 0) {
        AmStreamConnection::ConnectionType ctype = GetConnectionType(buffer, b_size);
        if(ctype == AmStreamConnection::UNKNOWN_CONN) {
            CLASS_WARN("Unknown packet type, ignore it");
            return;
        }

        log_rcvd_packet((char*)buffer, b_size, saddr, ctype);

        vector<AmStreamConnection*> conns_by_type;
        for(auto conn : connections) {
            if(conn->isUseConnection(ctype)) {
                conns_by_type.push_back(conn);
            }
        }

        AmStreamConnection* s_conn = 0;
        for(auto conn : conns_by_type) {
            if(conn->isAddrConnection(&saddr)) {
                s_conn = conn;
                break;
            }
        }

        if(!s_conn && !conns_by_type.empty()) {
            s_conn = conns_by_type[0];
        }

        if(!s_conn) {
            char error[100];
            sprintf(error, "doesn't found connection by type %d, ignore packet with type %d", type, ctype);
            getRtpStream()->onErrorRtpTransport(error, this);
            return;
        }

        s_conn->handleConnection(buffer, b_size, &saddr, recv_time);
    }
}

AmStreamConnection::ConnectionType AmRtpTransport::GetConnectionType(unsigned char* buf, int size)
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

    unsigned short type = htons(*(unsigned short*)buf);
    return IS_STUN_MESSAGE(type);
}

bool AmRtpTransport::isDTLSMessage(unsigned char* buf, unsigned int size)
{
    if(!size) {
        return false;
    }

    Botan::TLS::Record_Type type = (Botan::TLS::Record_Type)*buf;
    return type == Botan::TLS::CHANGE_CIPHER_SPEC || type == Botan::TLS::ALERT ||
           type == Botan::TLS::HANDSHAKE || type == Botan::TLS::APPLICATION_DATA;
}

bool AmRtpTransport::isRTCPMessage(unsigned char* buf, unsigned int size)
{
    if(size < sizeof(rtp_hdr_t)) {
        return false;
    }

    rtp_hdr_t* rtp = (rtp_hdr_t*)buf;
    if(rtp->version == RTP_VERSION && IS_RTCP_PAYLOAD(rtp->pt)) {
        return true;
    }
    return false;
}

bool AmRtpTransport::isRTPMessage(unsigned char* buf, unsigned int size)
{
    if(size < sizeof(rtp_hdr_t)) {
        return false;
    }

    rtp_hdr_t* rtp = (rtp_hdr_t*)buf;
    if(rtp->version == RTP_VERSION && !IS_RTCP_PAYLOAD(rtp->pt)) {
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

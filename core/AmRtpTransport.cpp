#include "AmRtpTransport.h"
#include "AmLcConfig.h"
#include "AmRtpReceiver.h"
#include "AmSrtpConnection.h"
#include "AmStunClient.h"

#include <sys/ioctl.h>
#include "AmRtpPacket.h"
#include "rtp/rtp.h"
#include "sip/raw_sender.h"

#define RTCP_PAYLOAD_MIN 72
#define RTCP_PAYLOAD_MAX 76
#define IS_RTCP_PAYLOAD(p) ((p) >= RTCP_PAYLOAD_MIN && (p) <= RTCP_PAYLOAD_MAX)

AmRtpTransport::AmRtpTransport(AmRtpStream* _stream, int _if, AddressType type)
    : stream(_stream)
    , l_if(_if)
    , lproto_id(-1)
    , l_port(0)
    , l_sd(0)
    , l_sd_ctx(-1)
    , logger(0)
    , relay_raw(false)
{
    string local_ip;
    int proto_id = AmConfig.media_ifs[l_if].findProto(type,MEDIA_info::RTP);
    if(proto_id >= 0) {
        local_ip = AmConfig.media_ifs[l_if].proto_info[proto_id]->local_ip;
        lproto_id = proto_id;
    } else {
        CLASS_ERROR("AmRtpTransport: missed requested proto in choosen media interface");
        return;
    }

    if((local_ip[0] == '[') &&
      (local_ip[local_ip.size() - 1] == ']') ) {
        local_ip.pop_back();
        local_ip.erase(local_ip.begin());
    }

    CLASS_DBG("local_ip = %s\n",local_ip.c_str());

    if (!am_inet_pton(local_ip.c_str(), &l_saddr)) {
        CLASS_ERROR("AmRtpTransport: Invalid IP address: %s", local_ip.c_str());
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
}

void AmRtpTransport::setLogger(msg_logger* _logger)
{
    if (logger) dec_ref(logger);
        logger = _logger;
    if (logger) inc_ref(logger);
}

void AmRtpTransport::setLocalPort(unsigned short p)
{
    if(l_port)
        return;

    int retry = 10;
    unsigned short port = 0;

    for(;retry; --retry) {

        if (!getLocalSocket())
            return;

        if(!p)
            port = AmConfig.media_ifs[l_if].proto_info[lproto_id]->getNextRtpPort();
        else
            port = p;

        am_set_port(&l_saddr,port);
        if(bind(l_sd,(const struct sockaddr*)&l_saddr,SA_len(&l_saddr))) {
            CLASS_DBG("bind: %s\n",strerror(errno));
            goto try_another_port;
        }

        break;

try_another_port:
        close(l_sd);
        l_sd = 0;
    }

    int true_opt = 1;
    if (!retry){
        CLASS_ERROR("could not find a free port\n");
        throw string("could not find a free port");
    }

    // rco: does that make sense after bind() ????
    if(setsockopt(l_sd, SOL_SOCKET, SO_REUSEADDR,
        (void*)&true_opt, sizeof (true_opt)) == -1)
    {
        CLASS_ERROR("%s\n",strerror(errno));
        close(l_sd);
        l_sd = 0;
        throw string ("while setting local address reusable.");
    }

    int tos = AmConfig.media_ifs[l_if].proto_info[lproto_id]->tos_byte;
    if(tos && setsockopt(l_sd, IPPROTO_IP, IP_TOS,  &tos, sizeof(tos)) == -1)
    {
        CLASS_WARN("failed to set IP_TOS for descriptors %d",l_sd);
    }

    l_port = port;

    if(!p) {
        l_sd_ctx = AmRtpReceiver::instance()->addStream(l_sd, this,l_sd_ctx);
        if(l_sd_ctx < 0) {
            CLASS_ERROR("can't add to RTP receiver (%s:%i)\n",
                get_addr_str((sockaddr_storage*)&l_saddr).c_str(),l_port);
        } else {
            CLASS_DBG("added to RTP receiver (%s:%i)\n",
                get_addr_str((sockaddr_storage*)&l_saddr).c_str(),l_port);
        }
    }
}

void AmRtpTransport::getLocalAddr(struct sockaddr_storage* addr)
{
    if(!l_port) {
        setLocalPort();
    }

    memcpy(addr, &l_saddr, sizeof(sockaddr_storage));
}

int AmRtpTransport::getLocalPort()
{
    if(!l_port)
        setLocalPort();

    return l_port;
}

int AmRtpTransport::getLocalSocket()
{
    if (l_sd)
        return l_sd;

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

void AmRtpTransport::setRawRelay(bool enable)
{
    CLASS_DBG("%sabled RAW relay\n", enable ? "en" : "dis");
    relay_raw = enable;
}

bool AmRtpTransport::isRawRelay()
{
    return relay_raw;
}

int AmRtpTransport::init(const SdpMedia& local, const SdpMedia& remote, bool force_passive_mode)
{
    return 0;
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

void AmRtpTransport::log_rcvd_packet(const char *buffer, int len, struct sockaddr_storage &recv_addr)
{
    static const cstring empty;
    if (logger)
        logger->log((const char *)buffer, len, &recv_addr, &l_saddr, empty);
}

void AmRtpTransport::log_sent_packet(const char *buffer, int len, struct sockaddr_storage &send_addr)
{
    static const cstring empty;
    if (logger)
        logger->log((const char *)buffer, len, &l_saddr, &send_addr, empty);
}

int AmRtpTransport::send(sockaddr_storage* raddr, unsigned char* buf, int size)
{
    log_sent_packet((char*)buf, size, *raddr);

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
        AmStreamConnection::ConnectionType type = GetConnectionType(buffer, b_size);
        if(type == AmStreamConnection::UNKNOWN_CONN) {
            CLASS_WARN("Unknown packet type, ignore it");
            return;
        }

        log_rcvd_packet((char*)buffer, b_size, saddr);

        vector<AmStreamConnection*> conns_by_type;
        for(auto conn : connections) {
            if(conn->isUseConnection(type)) {
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
            CLASS_WARN("doesn't found connection by type %d, ignore packet", type);
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

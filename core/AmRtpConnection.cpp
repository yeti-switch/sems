#include "AmRtpConnection.h"
#include "AmRtpTransport.h"
#include "AmLcConfig.h"
#include "AmRtpStream.h"

AmStreamConnection::AmStreamConnection(AmRtpTransport* _transport, const string& remote_addr, int remote_port, ConnectionType type)
    : transport(_transport)
    , parent(0)
    , r_host(remote_addr)
    , r_port(remote_port)
    , conn_type(type)
    , passive(false)
    , passive_set_time{0}
    , passive_packets(0)
{
    resolveRemoteAddress(remote_addr, remote_port);
}

AmStreamConnection::AmStreamConnection(AmStreamConnection* _parent, const string& remote_addr, int remote_port, ConnectionType type)
    : transport(_parent->transport)
    , parent(_parent)
    , r_host(remote_addr)
    , r_port(remote_port)
    , conn_type(type)
    , passive(false)
    , passive_set_time{0}
    , passive_packets(0)
{
    resolveRemoteAddress(remote_addr, remote_port);
}

AmStreamConnection::~AmStreamConnection()
{
}

bool AmStreamConnection::isUseConnection(ConnectionType type)
{
    return type == conn_type;
}

bool AmStreamConnection::isAddrConnection(struct sockaddr_storage* recv_addr)
{
    if(recv_addr->ss_family == AF_INET)
        return memcmp(&r_addr, recv_addr, sizeof(sockaddr_in) - sizeof(sockaddr_in::sin_zero)) == 0;
    else if(recv_addr->ss_family == AF_INET6)
        return memcmp(&r_addr, recv_addr, sizeof(sockaddr_in6)) == 0;
    return false;
}

AmStreamConnection::ConnectionType AmStreamConnection::getConnType()
{
    return conn_type;
}

int AmStreamConnection::send(AmRtpPacket* packet)
{
    return transport->send(&r_addr, packet->getBuffer(), packet->getBufferSize(), getConnType());
}

void AmStreamConnection::resolveRemoteAddress(const string& remote_addr, int remote_port)
{
    /* inet_aton only supports dot-notation IP address strings... but an RFC
     * 4566 unicast-address, as found in c=, can be an FQDN (or other!).
     */
    struct sockaddr_storage ss;
    AddressType addr_type = AmConfig.media_ifs[transport->getLocalIf()].proto_info[transport->getLocalProtoId()]->type_ip;
    dns_handle dh;
    dns_priority priority = IPv4_only;
    if(addr_type == AT_V6) {
        priority = IPv6_only;
    }
    if (!remote_addr.empty() && resolver::instance()->resolve_name(remote_addr.c_str(),&dh,&ss,priority) < 0) {
        WARN("Address not valid (host: %s).\n", remote_addr.c_str());
        throw string("invalid address") + remote_addr;
    }

    if(remote_port) {
        memcpy(&r_addr,&ss,sizeof(struct sockaddr_storage));
        am_set_port(&r_addr,r_port);
    }

    mute = ((r_addr.ss_family == AF_INET) &&
            (SAv4(&r_addr)->sin_addr.s_addr == INADDR_ANY)) ||
           ((r_addr.ss_family == AF_INET6) &&
            IN6_IS_ADDR_UNSPECIFIED(&SAv6(&r_addr)->sin6_addr));
}

void AmStreamConnection::handleSymmetricRtp(struct sockaddr_storage* recv_addr)
{
    if(parent) parent->handleSymmetricRtp(recv_addr);

    if(passive)
    {
        uint64_t now = last_recv_time.tv_sec*1000-last_recv_time.tv_usec/1000,
                 set_time = passive_set_time.tv_sec*1000-passive_set_time.tv_usec/1000;
        if(AmConfig.symmetric_rtp_mode == ConfigContainer::SM_RTP_PACKETS &&
           passive_packets < (unsigned int)AmConfig.symmetric_rtp_packets) {
            passive_packets++;
            return;
        } else if(AmConfig.symmetric_rtp_mode == ConfigContainer::SM_RTP_DELAY &&
           now - set_time < (uint64_t)AmConfig.symmetric_rtp_delay) {
            return;
        }

        // symmetric RTP
        string addr_str = get_addr_str(recv_addr);
        unsigned short port = am_get_port(recv_addr);
        const char* prot = (conn_type == RTP_CONN) ? "RTP" : "RTCP";
        if (isAddrConnection(recv_addr)) {
            setRAddr(addr_str, port);
            if(!transport->getRtpStream()->isSymmetricRtpEndless()) {
                CLASS_DBG("Symmetric %s: setting new remote address: %s:%i\n", prot, addr_str.c_str(),port);
            }
        } else {
            if(!transport->getRtpStream()->isSymmetricRtpEndless()) {
                CLASS_DBG("Symmetric %s: remote end sends %s from advertised address."
                    " Leaving passive mode.\n",prot,prot);
            }
        }

        // avoid comparing each time sender address
        // don't switch to passive mode if endless switching flag set
        if(!transport->getRtpStream()->isSymmetricRtpEndless()){
            passive = false;
        }
    }
}

void AmStreamConnection::setPassiveMode(bool p)
{
    if(p) {
        memcpy(&passive_set_time, &last_recv_time, sizeof(struct timeval));
        passive_packets = 0;
    }
    passive = p;
    if (p) {
        CLASS_DBG("The other UA is NATed or passive mode forced: switched to passive mode.\n");
    } else {
        CLASS_DBG("Passive mode not activated.\n");
    }
}

AmRtpConnection::AmRtpConnection(AmRtpTransport* _transport, const string& remote_addr, int remote_port)
    : AmStreamConnection(_transport, remote_addr, remote_port, AmStreamConnection::RTP_CONN)
{
}

AmRtpConnection::AmRtpConnection(AmStreamConnection* _parent, const string& remote_addr, int remote_port)
    : AmStreamConnection(_parent, remote_addr, remote_port, AmStreamConnection::RTP_CONN)
{
}

AmRtpConnection::~AmRtpConnection()
{
}

void AmRtpConnection::handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time)
{
    handleSymmetricRtp(recv_addr);

    struct timeval now;
    struct timeval diff;
    gettimeofday(&now,NULL);
    timersub(&now,&last_recv_time,&diff);

    sockaddr_storage laddr;
    transport->getLocalAddr(&laddr);
    AmRtpPacket* p = transport->getRtpStream()->createRtpPacket();
    p->recv_time = recv_time;
    p->relayed = false;
    p->setAddr(recv_addr);
    p->setLocalAddr(&laddr);
    p->setBuffer(data, size);
    transport->onRtpPacket(p, parent ? parent : this);
}

AmRtcpConnection::AmRtcpConnection(AmRtpTransport* _transport, const string& remote_addr, int remote_port)
    : AmStreamConnection(_transport, remote_addr, remote_port, AmStreamConnection::RTCP_CONN)
{
}

AmRtcpConnection::AmRtcpConnection(AmStreamConnection* _parent, const string& remote_addr, int remote_port)
    : AmStreamConnection(_parent, remote_addr, remote_port, AmStreamConnection::RTCP_CONN)
{
}

AmRtcpConnection::~AmRtcpConnection()
{
}

void AmRtcpConnection::handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time)
{
    handleSymmetricRtp(recv_addr);

    sockaddr_storage laddr;
    transport->getLocalAddr(&laddr);
    AmRtpPacket* p = transport->getRtpStream()->createRtpPacket();
    p->recv_time = recv_time;
    p->relayed = false;
    p->setAddr(recv_addr);
    p->setLocalAddr(&laddr);
    p->setBuffer(data, size);
    transport->onRtcpPacket(p, parent ? parent : this);
    transport->getRtpStream()->freeRtpPacket(p);
}


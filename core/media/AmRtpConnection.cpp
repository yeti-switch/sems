#include "AmRtpConnection.h"
#include "AmMediaTransport.h"
#include "AmLcConfig.h"
#include "AmRtpStream.h"

static string streamConnType2str(AmStreamConnection::ConnectionType type)
{
    switch (type) {
    case AmStreamConnection::RTP_CONN:   return "RTP";
    case AmStreamConnection::RTCP_CONN:  return "RTCP";
    case AmStreamConnection::DTLS_CONN:  return "DTLS";
    case AmStreamConnection::STUN_CONN:  return "STUN";
    case AmStreamConnection::RAW_CONN:   return "RAW";
    case AmStreamConnection::ZRTP_CONN:  return "ZRTP";
    case AmStreamConnection::UDPTL_CONN: return "UDPTL";
    default:                             return "UNKNOWN";
    }
}

AmStreamConnection::AmStreamConnection(AmMediaTransport *_transport, const string &remote_addr, int remote_port,
                                       ConnectionType type)
    : transport(_transport)
    , parent(0)
    , r_host(remote_addr)
    , r_port(remote_port)
    , conn_type(type)
    , stream_is_ice_stream(transport->getRtpStream()->isIceStream())
    , stream_symmetric_rtp_endless(transport->getRtpStream()->isSymmetricRtpEndless())
    , passive(transport->getRtpStream()->isSymmetricRtpEnable())
    , active_raddr_packet_received(false)
    , passive_set_time{ 0, 0 }
    , passive_packets(0)
    , dropped_by_raddr_packets(0)
{
    CLASS_DBG("AmStreamConnection(transport:%p, remote_addr:'%s', port:%d, type %s)", to_void(_transport),
              remote_addr.data(), remote_port, streamConnType2str(type).c_str());
    bzero(&r_addr, sizeof(struct sockaddr_storage));
    r_port = 0;
    resolveRemoteAddress(remote_addr, remote_port);
}

AmStreamConnection::AmStreamConnection(AmStreamConnection *_parent, const string &remote_addr, int remote_port,
                                       ConnectionType type)
    : transport(_parent->transport)
    , parent(_parent)
    , r_host(remote_addr)
    , r_port(remote_port)
    , conn_type(type)
    , stream_is_ice_stream(transport->getRtpStream()->isIceStream())
    , stream_symmetric_rtp_endless(transport->getRtpStream()->isSymmetricRtpEndless())
    , passive(transport->getRtpStream()->isSymmetricRtpEnable())
    , active_raddr_packet_received(false)
    , passive_set_time{ 0, 0 }
    , passive_packets(0)
    , dropped_by_raddr_packets(0)
{
    CLASS_DBG("AmStreamConnection(parent: %p, remote_addr:'%s', port:%d, type %s)", to_void(_parent),
              remote_addr.data(), remote_port, streamConnType2str(type).c_str());
    bzero(&r_addr, sizeof(struct sockaddr_storage));
    r_port = 0;
    resolveRemoteAddress(remote_addr, remote_port);
}

AmStreamConnection::~AmStreamConnection() {}

bool AmStreamConnection::isUseConnection(ConnectionType type)
{
    return type == conn_type;
}

bool AmStreamConnection::isAddrConnection(struct sockaddr_storage *recv_addr) const
{
    if (recv_addr->ss_family == AF_INET) {
        return SAv4(&r_addr)->sin_port == SAv4(recv_addr)->sin_port &&
               SAv4(&r_addr)->sin_addr.s_addr == SAv4(recv_addr)->sin_addr.s_addr;
    } else if (recv_addr->ss_family == AF_INET6) {
        return SAv6(&r_addr)->sin6_port == SAv6(recv_addr)->sin6_port &&
               IN6_ARE_ADDR_EQUAL(&SAv6(&r_addr)->sin6_addr, &SAv6(recv_addr)->sin6_addr);
    }
    return false;
}


AmStreamConnection::ConnectionType AmStreamConnection::getConnType()
{
    return conn_type;
}

ssize_t AmStreamConnection::send(AmRtpPacket *packet)
{
    auto ret = transport->send(&r_addr, packet->getBuffer(), static_cast<int>(packet->getBufferSize()), getConnType());

    if (ret < 0) {
        if (AmConfig.rtp_send_errors_log_level >= 0) {
            _LOG(AmConfig.rtp_send_errors_log_level,
                 "AmStreamConnection::send: ret: %ld. r_addr:'%s':%hu, r_host:'%s', r_port: %d", ret,
                 get_addr_str(&r_addr).data(), am_get_port(&r_addr), r_host.data(), r_port);
        }
    }

    return ret;
}

void AmStreamConnection::setRAddr(const string &addr, unsigned short port)
{
    CLASS_DBG("setRAddr(%s,%hu) type:%d, endpoint: %s:%d", addr.data(), port, conn_type, r_host.data(), r_port);

    if (port != r_port || addr != r_host) {
        active_raddr_packet_received = false;
    }

    resolveRemoteAddress(addr, port);
}

void AmStreamConnection::resolveRemoteAddress(const string &remote_addr, int remote_port)
{
    /* inet_aton only supports dot-notation IP address strings... but an RFC
     * 4566 unicast-address, as found in c=, can be an FQDN (or other!).
     */
    struct sockaddr_storage ss;
    AddressType             addr_type =
        AmConfig.media_ifs[transport->getLocalIf()].proto_info[transport->getLocalProtoId()]->type_ip;
    dns_handle   dh;
    dns_priority priority = IPv4_only;

    if (addr_type == AT_V6) {
        priority = IPv6_only;
    }
    if (!remote_addr.empty() && resolver::instance()->resolve_name(remote_addr.c_str(), &dh, &ss, priority) < 0) {
        WARN("Address not valid (host: %s).", remote_addr.c_str());
        throw string("invalid address") + remote_addr;
    }
    r_host = remote_addr;

    if (remote_port) {
        // CLASS_DBG("change connection endpoint. conn_type:%d %s:%d -> %s:%d",
        //           conn_type,
        //           get_addr_str(&r_addr).data(), r_port,
        //           get_addr_str(&ss).data(), remote_port);
        memcpy(&r_addr, &ss, sizeof(struct sockaddr_storage));
        am_set_port(&r_addr, remote_port);
        r_port = remote_port;
    }

    mute = ((r_addr.ss_family == AF_INET) && (SAv4(&r_addr)->sin_addr.s_addr == INADDR_ANY)) ||
           ((r_addr.ss_family == AF_INET6) && IN6_IS_ADDR_UNSPECIFIED(&SAv6(&r_addr)->sin6_addr));
}

void AmStreamConnection::process_packet(uint8_t *data, unsigned int size, struct sockaddr_storage *recv_addr,
                                        struct timeval recv_time)
{
    handleSymmetricRtp(recv_addr, &recv_time);
    if (!passive && !isAddrConnection(recv_addr)) {
        // got packet from unknown remote addr. ignore it
        auto stream = transport->getRtpStream();
        stream->inc_drop_pack();
        if ((dropped_by_raddr_packets++ % 1500) == 0 /* 1/0.02*10 (every 10 seconds) */) {
            CLASS_DBG("%u packets dropped by raddr check. "
                      "packet raddr: %s:%hu, connection raddr: %s:%hu, stream:%p",
                      dropped_by_raddr_packets, get_addr_str(recv_addr).data(), am_get_port(recv_addr),
                      get_addr_str(&r_addr).data(), am_get_port(&r_addr), stream);
        }
        return;
    }

    memcpy(&last_recv_time, &recv_time, sizeof(struct timeval));
    handleConnection(data, size, recv_addr, recv_time);
}

void AmStreamConnection::handleSymmetricRtp(struct sockaddr_storage *recv_addr, struct timeval *rv_time)
{
    if (stream_is_ice_stream)
        return;

    if (parent)
        parent->handleSymmetricRtp(recv_addr, rv_time);

    if (!passive) {
        // active mode
        if (!active_raddr_packet_received && isAddrConnection(recv_addr)) {
            active_raddr_packet_received = true;
            transport->getRtpStream()->onRtpEndpointLearned();
        }
        return;
    }

    // passive mode

    auto stream          = transport->getRtpStream();
    auto recv_from_raddr = isAddrConnection(recv_addr);

    switch (AmConfig.symmetric_rtp_mode) {
    case ConfigContainer::SM_RTP_PACKETS:
        if (passive_packets < (unsigned int)AmConfig.symmetric_rtp_packets) {
            if (recv_from_raddr) {
                if (stream_symmetric_rtp_endless) {
                    // clear passive counter on the packet from the actual r_addr
                    passive_packets = 0;
                    return;
                }
                // no return to leave passive mode immediately
            } else {
                passive_packets++;
                return;
            }
        }
        // no return when packets count condition is reached
        break;
    case ConfigContainer::SM_RTP_DELAY:
    {
        struct timeval delta;
        timersub(&last_recv_time, &passive_set_time, &delta);
        int delta_ms = delta.tv_sec * 1000 + delta.tv_usec / 1000;

        if (delta_ms < AmConfig.symmetric_rtp_delay) {
            if (recv_from_raddr) {
                if (stream_symmetric_rtp_endless) {
                    // clear passive time on the packet from the actual r_addr
                    memcpy(&passive_set_time, &last_recv_time, sizeof(struct timeval));
                    return;
                }
                // no return to leave passive mode immediately
            } else {
                // no actions for delay condition
                return;
            }
        }
        // no return when delay condition is reached
    } break;
    default:
        // unexpected symmetric_rtp_mode
        return;
    }

    // symmetric RTP condition reached

    passive_packets = 0;
    memcpy(&passive_set_time, &last_recv_time, sizeof(struct timeval));

    const char *proto_str = (conn_type == RTP_CONN) ? "RTP" : "RTCP";

    if (!stream_symmetric_rtp_endless) {
        // normal mode
        if (!recv_from_raddr) {
            string         addr_str = get_addr_str(recv_addr);
            unsigned short port     = am_get_port(recv_addr);
            setRAddr(addr_str, port);
            CLASS_DBG("Symmetric %s: set new remote address: %s:%i. Leave passive mode", proto_str, addr_str.c_str(),
                      port);
        } else {
            CLASS_DBG("Symmetric %s: received packet from the advertised address. Leave passive mode", proto_str);
        }
        passive = false;
        stream->onLeavePassiveMode();
    } else {
        // endless mode
        string         addr_str = get_addr_str(recv_addr);
        unsigned short port     = am_get_port(recv_addr);
        setRAddr(addr_str, port);
        CLASS_DBG("Symmetric %s: set new remote address: %s:%i. Stay in passive mode", proto_str, addr_str.c_str(),
                  port);

        stream->onRtpEndpointLearned();
    }
}

void AmStreamConnection::getInfo(AmArg &ret)
{
    if (conn_type == RTP_CONN)
        ret["type"] = "rtp";
    else if (conn_type == RTCP_CONN)
        ret["type"] = "rtcp";
    else if (conn_type == STUN_CONN)
        ret["type"] = "stun";
    else if (conn_type == DTLS_CONN)
        ret["type"] = "dtls";
    else if (conn_type == UDPTL_CONN)
        ret["type"] = "udptl";
    else if (conn_type == ZRTP_CONN)
        ret["type"] = "zrtp";
    else if (conn_type == RAW_CONN)
        ret["type"] = "raw";
    ret["passive"]     = passive;
    ret["remote_addr"] = r_host;
    ret["remote_port"] = r_port;
}

void AmStreamConnection::setPassiveMode(bool p)
{
    if (p) {
        memcpy(&passive_set_time, &last_recv_time, sizeof(struct timeval));
        passive_packets = 0;
    }
    passive = p;
    if (p) {
        CLASS_DBG("The other UA is NATed or passive mode forced: switched to passive mode.");
    } else {
        CLASS_DBG("Passive mode not activated.");
    }
}

string AmStreamConnection::connType2Str(ConnectionType type)
{
    switch (type) {
    case RTP_CONN:     return "RTP";
    case RTCP_CONN:    return "RTCP";
    case STUN_CONN:    return "STUN";
    case DTLS_CONN:    return "DTLS";
    case UDPTL_CONN:   return "UDPTL";
    case ZRTP_CONN:    return "ZRTP";
    case RAW_CONN:     return "RAW";
    case UNKNOWN_CONN: return "UNKNOWN";
    };
}

AmRawConnection::AmRawConnection(AmMediaTransport *_transport, const string &remote_addr, int remote_port)
    : AmStreamConnection(_transport, remote_addr, remote_port, AmStreamConnection::RAW_CONN)
{
}

void AmRawConnection::handleConnection(uint8_t *data, unsigned int size, struct sockaddr_storage *recv_addr,
                                       struct timeval recv_time)
{
    sockaddr_storage laddr;
    transport->getLocalAddr(&laddr);

    AmRtpPacket *p = transport->getRtpStream()->createRtpPacket();
    if (!p)
        return;

    p->recv_time = recv_time;
    p->relayed   = false;
    p->setAddr(recv_addr);
    p->setLocalAddr(&laddr);
    p->setBuffer(data, size);
    transport->onRawPacket(p, this);
}


AmRtpConnection::AmRtpConnection(AmMediaTransport *_transport, const string &remote_addr, int remote_port)
    : AmStreamConnection(_transport, remote_addr, remote_port, AmStreamConnection::RTP_CONN)
{
}

AmRtpConnection::AmRtpConnection(AmStreamConnection *_parent, const string &remote_addr, int remote_port)
    : AmStreamConnection(_parent, remote_addr, remote_port, AmStreamConnection::RTP_CONN)
{
}

AmRtpConnection::~AmRtpConnection() {}

void AmRtpConnection::handleConnection(uint8_t *data, unsigned int size, struct sockaddr_storage *recv_addr,
                                       struct timeval recv_time)
{
    sockaddr_storage laddr;
    transport->getLocalAddr(&laddr);

    AmRtpPacket *p = transport->getRtpStream()->createRtpPacket();
    if (!p)
        return;

    p->recv_time = recv_time;
    p->relayed   = false;
    p->setAddr(recv_addr);
    p->setLocalAddr(&laddr);
    p->setBuffer(data, size);
    transport->onRtpPacket(p, parent ? parent : this);
}

AmRtcpConnection::AmRtcpConnection(AmMediaTransport *_transport, const string &remote_addr, int remote_port)
    : AmStreamConnection(_transport, remote_addr, remote_port, AmStreamConnection::RTCP_CONN)
{
}

AmRtcpConnection::AmRtcpConnection(AmStreamConnection *_parent, const string &remote_addr, int remote_port)
    : AmStreamConnection(_parent, remote_addr, remote_port, AmStreamConnection::RTCP_CONN)
{
}

AmRtcpConnection::~AmRtcpConnection() {}

void AmRtcpConnection::handleConnection(uint8_t *data, unsigned int size, struct sockaddr_storage *recv_addr,
                                        struct timeval recv_time)
{
    sockaddr_storage laddr;
    transport->getLocalAddr(&laddr);
    AmRtpPacket *p = transport->getRtpStream()->createRtpPacket();
    if (!p)
        return;
    p->recv_time = recv_time;
    p->relayed   = false;
    p->setAddr(recv_addr);
    p->setLocalAddr(&laddr);
    p->setBuffer(data, size);
    transport->onRtcpPacket(p, parent ? parent : this);
    transport->getRtpStream()->freeRtpPacket(p);
}

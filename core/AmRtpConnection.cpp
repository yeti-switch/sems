#include "AmRtpConnection.h"
#include "AmRtpTransport.h"
#include "AmLcConfig.h"

AmStreamConnection::AmStreamConnection(AmRtpTransport* _transport, struct sockaddr_storage* remote_addr, ConnectionType type)
    : transport(_transport), r_addr(*remote_addr), conn_type(type)
{
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
        return memcmp(&r_addr, recv_addr, sizeof(sockaddr_in)) == 0;
    else if(recv_addr->ss_family == AF_INET6)
        return memcmp(&r_addr, recv_addr, sizeof(sockaddr_in6)) == 0;
    return false;
}

AmRtpConnection::AmRtpConnection(AmRtpTransport* _transport, struct sockaddr_storage* remote_addr)
    : AmStreamConnection(_transport, remote_addr, AmStreamConnection::RTP_CONN)
    , passive(false)
    , passive_set_time{0}
    , passive_packets(0)
    , symmetric_rtp_endless(false)
{
}

AmRtpConnection::~AmRtpConnection()
{
}

void AmRtpConnection::setSymmetricRtpEndless(bool endless)
{
    CLASS_DBG("%sabled endless symmetric RTP switching\n",
        endless ? "en":"dis");
     symmetric_rtp_endless = endless;
}

void AmRtpConnection::handleSymmetricRtp(struct sockaddr_storage* recv_addr)
{
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
        const char* prot = (conn_type == RTP_CONN) ? "RTCP" : "RTP";
        if (isAddrConnection(recv_addr)) {
            memcpy(&r_addr, recv_addr, r_addr.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6));
            if(!symmetric_rtp_endless) {
                CLASS_DBG("Symmetric %s: setting new remote address: %s:%i\n", prot, addr_str.c_str(),port);
            }
        } else {
            if(!symmetric_rtp_endless) {
                CLASS_DBG("Symmetric %s: remote end sends %s from advertised address."
                    " Leaving passive mode.\n",prot,prot);
            }
        }

        // avoid comparing each time sender address
        // don't switch to passive mode if endless switching flag set
        if(!symmetric_rtp_endless){
            passive = false;
        }
    }
}

void AmRtpConnection::handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr)
{
    struct timeval now;
    struct timeval diff;
    gettimeofday(&now,NULL);
    timersub(&now,&last_recv_time,&diff);
}

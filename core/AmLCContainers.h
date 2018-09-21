#ifndef AM_LC_CONTAINERS_H
#define AM_LC_CONTAINERS_H

#include <stdint.h>
#include <string>
#include <vector>
#include <list>
#include "sip/transport.h"
#include "sems.h"

class IP_info
{
public:
    enum IP_type
    {
        UNDEFINED,
        IPv4,
        IPv6
    };

    IP_info()
    : type_ip(UNDEFINED), net_if_idx(0), dscp(0), sig_sock_opts(0), tos_byte(0){}
    IP_info(const IP_info& info)
    : local_ip(info.local_ip)
    , public_ip(info.public_ip)
    , type_ip(info.type_ip)
    , net_if(info.net_if)
    , net_if_idx(info.net_if_idx)
    , dscp(info.dscp)
    , sig_sock_opts(info.sig_sock_opts)
    , tos_byte(info.tos_byte){}
    virtual ~IP_info(){}

    /** Used for binding socket */
    std::string local_ip;

    /** Used in Contact-HF */
    std::string public_ip;

    /** Used ip type socket */
    IP_type type_ip;

    /** Network interface name and index */
    std::string  net_if;
    unsigned int net_if_idx;

    /** options for the signaling socket
     * (@see socket_options)
     */
    unsigned int sig_sock_opts;

    /** DSCP */
    uint8_t dscp;
    int tos_byte;

    std::string getIP() {
      return public_ip.empty() ? local_ip : public_ip;
    }

    virtual IP_info* Clone(){
        return new IP_info(*this);
    }
};

class SIP_info : public IP_info
{
public:
    enum SIP_type
    {
        UDP,
        TCP
    };

    SIP_info(SIP_type type)
    : type(type), local_port(0){}
    SIP_info(const SIP_info& info)
    : IP_info(info)
    , type(info.type)
    , local_port(info.local_port)
    , acl(info.acl)
    , opt_acl(info.opt_acl){}
    virtual ~SIP_info(){}

    SIP_type type;

    unsigned int local_port;

    trsp_acl acl;
    trsp_acl opt_acl;

    std::string toStr() const {
        if(type == SIP_info::TCP) {
            return "TCP";
        } else if(type == SIP_info::UDP) {
            return "UDP";
        }

        return "";
    }

    virtual IP_info* Clone(){
        return new SIP_info(*this);
    }
};

class SIP_UDP_info : public SIP_info
{
public:
    SIP_UDP_info() : SIP_info(UDP){}
    SIP_UDP_info(const SIP_UDP_info& info) : SIP_info(info){}
    virtual ~SIP_UDP_info(){}

    static SIP_UDP_info* toSIP_UDP(SIP_info* info)
    {
        if(info->type == UDP) {
            return static_cast<SIP_UDP_info*>(info);
        }
        return 0;
    }

    virtual IP_info* Clone(){
        return new SIP_UDP_info(*this);
    }
};

class SIP_TCP_info : public SIP_info
{
public:
    SIP_TCP_info()
    : SIP_info(TCP), tcp_connect_timeout(DEFAULT_TCP_CONNECT_TIMEOUT), tcp_idle_timeout(DEFAULT_TCP_IDLE_TIMEOUT){}
    SIP_TCP_info(const SIP_TCP_info& info)
    : SIP_info(info), tcp_connect_timeout(info.tcp_connect_timeout), tcp_idle_timeout(info.tcp_idle_timeout){}
    virtual ~SIP_TCP_info(){}

    unsigned int tcp_connect_timeout;
    unsigned int tcp_idle_timeout;

    static SIP_TCP_info* toSIP_TCP(SIP_info* info)
    {
        if(info->type == TCP) {
            return static_cast<SIP_TCP_info*>(info);
        }
        return 0;
    }

    virtual IP_info* Clone(){
        return new SIP_TCP_info(*this);
    }
};

class MEDIA_info : public IP_info
{
public:
    enum MEDIA_type
    {
        RTP,
        RTSP
    };

    MEDIA_info(MEDIA_type type)
    : mtype(type), low_port(RTP_LOWPORT), high_port(RTP_HIGHPORT), next_rtp_port(-1){}
    MEDIA_info(const MEDIA_info& info)
    : IP_info(info)
    , mtype(info.mtype)
    , low_port(info.low_port)
    , high_port(info.high_port)
    , next_rtp_port(info.next_rtp_port){}
    virtual ~MEDIA_info(){}

    MEDIA_type mtype;
    unsigned int low_port;
    unsigned int high_port;

    int getNextRtpPort()
    {
        int port=0;

        next_rtp_port_mut.lock();
        if(next_rtp_port < 0){
            next_rtp_port = low_port;
        }

        port = next_rtp_port & 0xfffe;
        next_rtp_port += 2;

        if(next_rtp_port >= (int)high_port){
            next_rtp_port = low_port;
        }
        next_rtp_port_mut.unlock();

        return port;
    }

    std::string toStr() const {
        if(mtype == MEDIA_info::RTP) {
            return "RTP";
        } else if(mtype == MEDIA_info::RTSP) {
            return "RTSP";
        }

        return "";
    }

    virtual IP_info* Clone(){
        return new MEDIA_info(*this);
    }
private:
    int next_rtp_port;
    AmMutex next_rtp_port_mut;
};

class RTP_info : public MEDIA_info
{
public:
    RTP_info() : MEDIA_info(RTP){}
    RTP_info(const RTP_info& info) : MEDIA_info(info){}
    virtual ~RTP_info(){}

    static RTP_info* toMEDIA_RTP(MEDIA_info* info)
    {
        if(info->mtype == RTP) {
            return static_cast<RTP_info*>(info);
        }
        return 0;
    }

    virtual IP_info* Clone(){
        return new RTP_info(*this);
    }
};

class RTSP_info : public MEDIA_info
{
public:
    RTSP_info() : MEDIA_info(RTSP){}
    RTSP_info(const RTSP_info& info) : MEDIA_info(info){}
    virtual ~RTSP_info(){}

    static RTSP_info* toMEDIA_RTSP(MEDIA_info* info)
    {
        if(info->mtype == RTSP) {
            return static_cast<RTSP_info*>(info);
        }
        return 0;
    }

    virtual IP_info* Clone(){
        return new RTSP_info(*this);
    }
};

template<typename ProtoInfo>
class PI_interface
{
public:
    PI_interface(){}
    PI_interface(const PI_interface<ProtoInfo>& info)
    {
        operator = (info);
    }
    virtual ~PI_interface()
    {
        for(auto& info : proto_info) {
            delete info;
        }
    }
    void operator = (const PI_interface<ProtoInfo>& if_)
    {
        name = if_.name;
        for(auto& info : if_.proto_info)
        {
            proto_info.push_back(dynamic_cast<ProtoInfo>(info->Clone()));
        }
    }
    std::string name;
    std::vector<ProtoInfo> proto_info;
};

class SIP_interface : public PI_interface<SIP_info*>
{
public:
    SIP_interface(){}
    SIP_interface(const SIP_interface& sip)
    : PI_interface<SIP_info*>(sip)
    , default_media_if(sip.default_media_if){}
    virtual ~SIP_interface(){}

    void operator = (const SIP_interface& sip)
    {
        default_media_if = sip.default_media_if;
        PI_interface<SIP_info*>::operator = (sip);
    }

    std::string default_media_if;
};

typedef PI_interface<MEDIA_info*> MEDIA_interface;

class IPAddr
{
public:
    IPAddr(const string& addr, const short family)
        : addr(addr), family(family) {}

    IPAddr(const IPAddr& ip)
        : addr(ip.addr), family(ip.family) {}

    std::string addr;
    short  family;
};

struct SysIntf
{
    std::string       name;
    std::list<IPAddr> addrs;
    // identical to those returned by SIOCGIFFLAGS
    unsigned int flags;
    unsigned int mtu;
};

#endif/*AM_LC_CONTAINERS_H*/

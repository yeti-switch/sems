#ifndef AM_LC_CONTAINERS_H
#define AM_LC_CONTAINERS_H

#include <string>
#include <vector>
#include <functional>
#include <list>
#include <limits>
#include <cstdint>
#include <atomic>

#include "sems.h"
#include "AmStatistics.h"
#include "AmSdp.h"
#include "sip/transport.h"
#include "sip/ssl_settings.h"

#include "bitops.h"

#ifdef WITH_ZRTP
extern "C" {
    #include <bzrtp/bzrtp.h>
}
#endif/*WITH_ZRTP*/

class IP_info
{
public:
    IP_info()
    : type_ip(AT_NONE),
      net_if_idx(0),
      dscp(0),
      sig_sock_opts(0),
      tos_byte(0)
    {}

    IP_info(const IP_info& info) = delete;

    virtual ~IP_info(){}

    /** Used for binding socket */
    std::string local_ip;

    /** Used in Contact-HF/Via-HF */
    std::string public_ip;

    /** Used in Contact-HF/Via-HF instead of public_ip if set */
    std::string public_domain;

    bool announce_port;

    /** Used ip type socket */
    AddressType type_ip;

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

    virtual std::string getHost() {
      return public_domain.empty() ? getIP() : public_domain;
    }

    std::string ipTypeToStr() const {
        if(type_ip == AT_V4) {
            return "IPv4";
        } else if(type_ip == AT_V6) {
            return "IPv6";
        }

        return "";
    }
};

class SIP_info : public IP_info
{
public:
    enum SIP_type
    {
        UNDEFINED = 0,
        UDP,
        TCP,
        TLS,
        WS,
        WSS
    };

    SIP_info(SIP_type type)
    : type(type), local_port(0){}
    SIP_info(const SIP_info& info) = delete;
    virtual ~SIP_info(){}

    SIP_type type;

    unsigned int local_port;

    trsp_acls acls;

    std::string transportToStr() const {
        if(type == SIP_info::TCP) {
            return "TCP";
        } else if(type == SIP_info::UDP) {
            return "UDP";
        } else if(type == SIP_info::TLS) {
            return "TLS";
        } else if(type == SIP_info::WS) {
            return "WS";
        } else if(type == SIP_info::WSS) {
            return "WSS";
        }

        return "";
    }
};

class SIP_UDP_info : public SIP_info
{
public:
    SIP_UDP_info() : SIP_info(UDP){}
    SIP_UDP_info(const SIP_UDP_info& info) = delete;
    virtual ~SIP_UDP_info(){}

    static SIP_UDP_info* toSIP_UDP(SIP_info* info)
    {
        if(info->type == UDP) {
            return static_cast<SIP_UDP_info*>(info);
        }
        return 0;
    }
};

class SIP_TCP_info : public SIP_info
{
protected:
    explicit SIP_TCP_info(SIP_info::SIP_type type)
    : SIP_info(type), tcp_connect_timeout(DEFAULT_TCP_CONNECT_TIMEOUT), tcp_idle_timeout(DEFAULT_IDLE_TIMEOUT){}
public:
    SIP_TCP_info()
    : SIP_info(TCP), tcp_connect_timeout(DEFAULT_TCP_CONNECT_TIMEOUT), tcp_idle_timeout(DEFAULT_IDLE_TIMEOUT){}
    SIP_TCP_info(const SIP_TCP_info& info) = delete;
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
};

class SIP_TLS_info : public SIP_TCP_info
{
protected:
    explicit SIP_TLS_info(SIP_info::SIP_type type)
    : SIP_TCP_info(type){}
public:
    SIP_TLS_info()
    : SIP_TCP_info(TLS){}
    SIP_TLS_info(const SIP_TLS_info& info) = delete;
    virtual ~SIP_TLS_info(){}

    tls_server_settings server_settings;
    tls_client_settings client_settings;

    static SIP_TLS_info* toSIP_TLS(SIP_info* info)
    {
        if(info->type == TLS || info->type == WSS) {
            return static_cast<SIP_TLS_info*>(info);
        }
        return 0;
    }
};

class WS_info
{
public:
    WS_info()
    : cors_mode(true){}
    WS_info(const WS_info& info)
    : cors_mode(info.cors_mode){}
    virtual ~WS_info(){}

    bool cors_mode;
};

class SIP_WS_info : public SIP_TCP_info, public WS_info
{
public:
    SIP_WS_info()
    : SIP_TCP_info(WS){}
    SIP_WS_info(const SIP_WS_info& info) = delete;
    virtual ~SIP_WS_info(){}

    static SIP_WS_info* toSIP_WS(SIP_info* info)
    {
        if(info->type == WS) {
            return static_cast<SIP_WS_info*>(info);
        }
        return 0;
    }
};

class SIP_WSS_info : public SIP_TLS_info, public WS_info
{
public:
    SIP_WSS_info()
    : SIP_TLS_info(WSS){}
    SIP_WSS_info(const SIP_WSS_info& info) = delete;
    virtual ~SIP_WSS_info(){}

    static SIP_WSS_info* toSIP_WSS(SIP_info* info)
    {
        if(info->type == WSS) {
            return static_cast<SIP_WSS_info*>(info);
        }
        return 0;
    }
};

class MEDIA_info : public IP_info
{
public:
    enum MEDIA_type
    {
        RTP = 0,
        RTSP
    };

    MEDIA_info(MEDIA_type type);
    MEDIA_info(const MEDIA_info& info) = delete;
    MEDIA_info(MEDIA_info&& info) = delete;
    virtual ~MEDIA_info();

    MEDIA_type mtype;
    unsigned short low_port;
    unsigned short high_port;

    std::string transportToStr() const {
        if(mtype == MEDIA_info::RTP) {
            return "RTP";
        } else if(mtype == MEDIA_info::RTSP) {
            return "RTSP";
        }

        return "";
    }

    virtual int prepare(const std::string &iface_name);
    virtual bool getNextRtpAddress(sockaddr_storage& ss) = 0;
    virtual void freeRtpAddress(const sockaddr_storage& ss) = 0;
    virtual void iterateUsedPorts(std::function<void(const std::string&, unsigned short, unsigned short, const std::string&)> cl) = 0;

    class PortMap {
    public:
        PortMap() = delete;
        PortMap(const PortMap &) = delete;
        PortMap(PortMap &&) = delete;

        PortMap(MEDIA_info& info_);

        unsigned short getNextRtpPort();
        void freeRtpPort(unsigned int port);
        void iterateUsedPorts(std::function<void(const std::string&,unsigned short, unsigned short, const std::string& )> cl);

        /* initialize variables for RTP ports pool management and validate ports range
        * returns 0 on success, 1 otherwise */
        int prepare(const std::string &iface_name);

        void copy_addr(sockaddr_storage& ss);
        bool match_addr(const sockaddr_storage& ss);

        void setAddress(const string &address_) { address = address_; }

        AmMutex lp;
        std::map<short, std::string> localtag_ports;

    private:
        DECLARE_BITMAP_ALIGNED(ports_state, (USHRT_MAX+BYTES_PER_LONG+1));
        unsigned long *ports_state_start_addr,
                    *ports_state_end_addr;
        std::atomic<unsigned long *> ports_state_current_addr;
        unsigned short start_edge_bit_it,
                    start_edge_bit_it_parity,
                    end_edge_bit_it;
        bool rtp_bit_parity;
        AtomicCounter *opened_ports_counter;

        MEDIA_info& info;
        std::string address;
        sockaddr_storage saddr;
    };
};

class RTP_info : public MEDIA_info
{
public:
    RTP_info()
      : MEDIA_info(RTP),
        srtp_enable(false),
        dtls_enable(false),
        zrtp_enable(false)
    {}
    RTP_info(const RTP_info& info) = delete;
    virtual ~RTP_info(){}

    static RTP_info* toMEDIA_RTP(MEDIA_info* info)
    {
        if(info->mtype == RTP) {
            return static_cast<RTP_info*>(info);
        }

        return 0;
    }

    std::list<PortMap> addresses;
    bool single_address;

    dtls_client_settings client_settings;
    dtls_server_settings server_settings;
    std::vector<CryptoProfile> profiles;
    bool srtp_enable;
    bool dtls_enable;

    void addMediaAddress(std::string &address);
    int prepare(const std::string &iface_name);
    bool getNextRtpAddress(sockaddr_storage& ss);
    void freeRtpAddress(const sockaddr_storage& ss);
    void iterateUsedPorts(std::function<void(const std::string&,unsigned short, unsigned short, const std::string& )> cl);

    virtual std::string getHost() {
        return public_domain.empty() ? "" : public_domain;
    }

    int zrtp_hash_from_str(const string& str) {
#ifdef WITH_ZRTP
        if(str == "S256") return ZRTP_HASH_S256;
        if(str == "S384") return ZRTP_HASH_S384;
        if(str == "N256") return ZRTP_HASH_N256;
        if(str == "N384") return ZRTP_HASH_N384;
#endif/*WITH_ZRTP*/
        return 0;
    }

    int zrtp_cipher_from_str(const string& str) {
#ifdef WITH_ZRTP
        if(str == "AES1") return ZRTP_CIPHER_AES1;
        if(str == "AES2") return ZRTP_CIPHER_AES2;
        if(str == "AES3") return ZRTP_CIPHER_AES3;
        if(str == "2FS1") return ZRTP_CIPHER_2FS1;
        if(str == "2FS2") return ZRTP_CIPHER_2FS2;
        if(str == "2FS3") return ZRTP_CIPHER_2FS3;
#endif/*WITH_ZRTP*/
        return 0;
    }

    int zrtp_authtag_from_str(const string& str) {
#ifdef WITH_ZRTP
        if(str == "HS32") return ZRTP_AUTHTAG_HS32;
        if(str == "HS80") return ZRTP_AUTHTAG_HS80;
        if(str == "SK32") return ZRTP_AUTHTAG_SK32;
        if(str == "SK64") return ZRTP_AUTHTAG_SK64;
#endif/*WITH_ZRTP*/
        return 0;
    }

    int zrtp_dhmode_from_str(const string& str) {
#ifdef WITH_ZRTP
        if(str == "DH2K") return ZRTP_KEYAGREEMENT_DH2k;
        if(str == "EC25") return ZRTP_KEYAGREEMENT_EC25;
        if(str == "DH3K") return ZRTP_KEYAGREEMENT_DH3k;
        if(str == "EC38") return ZRTP_KEYAGREEMENT_EC38;
        if(str == "EC52") return ZRTP_KEYAGREEMENT_EC52;
        if(str == "PRSH") return ZRTP_KEYAGREEMENT_Prsh;
        if(str == "MULT") return ZRTP_KEYAGREEMENT_Mult;
#endif/*WITH_ZRTP*/
        return 0;
    }

    int zrtp_sas_from_str(const string& str) {
#ifdef WITH_ZRTP
        if(str == "B32") return ZRTP_SAS_B32;
        if(str == "B256") return ZRTP_SAS_B256;
#endif/*WITH_ZRTP*/
        return 0;
    }

    bool zrtp_enable;
    std::vector<uint8_t> zrtp_hashes;
    std::vector<uint8_t> zrtp_ciphers;
    std::vector<uint8_t> zrtp_authtags;
    std::vector<uint8_t> zrtp_dhmodes;
    std::vector<uint8_t> zrtp_sas;
};

class RTSP_info : public MEDIA_info
{
    PortMap portmap;
public:
    RTSP_info()
      : MEDIA_info(RTSP)
      , portmap(*this)
    {}
    RTSP_info(const RTSP_info& info) = delete;
    virtual ~RTSP_info(){}

    int prepare(const std::string &iface_name);
    bool getNextRtpAddress(sockaddr_storage& ss);
    void freeRtpAddress(const sockaddr_storage& ss);
    void iterateUsedPorts(std::function<void(const std::string&,unsigned short, unsigned short, const std::string& )> cl);

    static RTSP_info* toMEDIA_RTSP(MEDIA_info* info)
    {
        if(info->mtype == RTSP) {
            return static_cast<RTSP_info*>(info);
        }
        return 0;
    }
};

template<typename ProtoInfo>
class PI_interface
{
public:
    PI_interface(){}
    PI_interface(const PI_interface<ProtoInfo>& info) = delete;
    PI_interface(PI_interface<ProtoInfo>&& info) = default;
    virtual ~PI_interface()
    {
        for(auto& info : proto_info) {
            delete info;
        }
    }

    std::string name;
    std::vector<ProtoInfo> proto_info;
    std::map<unsigned char, unsigned short> local_ip_proto2proto_idx;
};

class SIP_interface : public PI_interface<SIP_info*>
{
public:
    SIP_interface() {}
    SIP_interface(const SIP_interface& sip) = delete;
    SIP_interface(SIP_interface&& sip) = default;
    virtual ~SIP_interface() {}

    std::string default_media_if;

    int insertProtoMapping(
        SIP_info &info,
        unsigned short index)
    {
        unsigned char mask = static_cast<unsigned char>(info.type_ip | (info.type << 3));
        std::map<unsigned char, unsigned short>::iterator it = local_ip_proto2proto_idx.find(mask);
        if(it != local_ip_proto2proto_idx.end()) {
            ERROR("duplicate local signalling protocol %s/%s. replace existent one in the map",
                 proto_info[index]->ipTypeToStr().c_str(),
                 proto_info[index]->transportToStr().c_str());
            local_ip_proto2proto_idx[mask] = index;
        } else {
            local_ip_proto2proto_idx.emplace(mask, index);
        }
        return 0;
    }

    int findProto(
        AddressType address_type,
        SIP_info::SIP_type transport_type)
    {
        unsigned char mask = static_cast<unsigned char>(address_type | (transport_type << 3));
        auto addr_it = local_ip_proto2proto_idx.find(mask);
        if(addr_it != local_ip_proto2proto_idx.end()) {
            return addr_it->second;
        }
        return -1;
    }
};

class MEDIA_interface : public PI_interface<MEDIA_info*>
{
  public:
    int insertProtoMapping(
        MEDIA_info &info,
        unsigned short index)
    {
        unsigned char mask = static_cast<unsigned char>(info.type_ip | (info.mtype << 3));
        std::map<unsigned char, unsigned short>::iterator it = local_ip_proto2proto_idx.find(mask);
        if(it != local_ip_proto2proto_idx.end()) {
            ERROR("duplicate local media protocol %s/%s. replace existent one in the map",
                 proto_info[index]->ipTypeToStr().c_str(),
                 proto_info[index]->transportToStr().c_str());
            local_ip_proto2proto_idx[mask] = index;
        } else {
            local_ip_proto2proto_idx.emplace(mask, index);
        }
        return 0;
    }

    int findProto(
        AddressType address_type,
        MEDIA_info::MEDIA_type media_type)
    {
        unsigned char mask = static_cast<unsigned char>(
            address_type | (media_type << 3));
        auto addr_it = local_ip_proto2proto_idx.find(mask);
        if(addr_it != local_ip_proto2proto_idx.end()) {
            return addr_it->second;
        }
        return -1;
    }
};

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

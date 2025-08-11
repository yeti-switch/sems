#pragma once

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
#include "sip/ip_util.h"
#include "sip/transport.h"
#include "sip/ssl_settings.h"

#include "PortMap.h"

#ifdef WITH_ZRTP
extern "C" {
#include <bzrtp/bzrtp.h>
}
#endif /*WITH_ZRTP*/

class IP_info {
  public:
    IP_info()
        : type_ip(AT_NONE)
        , net_if_idx(0)
        , sig_sock_opts(0)
        , dscp(0)
        , tos_byte(0)
    {
    }

    IP_info(const IP_info &info) = delete;

    virtual ~IP_info() {}

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
    int     tos_byte;

    std::string getIP() { return public_ip.empty() ? local_ip : public_ip; }

    std::string getHost() { return public_domain.empty() ? getIP() : public_domain; }

    std::string ipTypeToStr() const
    {
        if (type_ip == AT_V4) {
            return "IPv4";
        } else if (type_ip == AT_V6) {
            return "IPv6";
        }

        return "";
    }

    virtual std::string transportToStr() const = 0;
};

class SIP_info : public IP_info {
  public:
    enum SIP_type { UNDEFINED = 0, UDP, TCP, TLS, WS, WSS };

    SIP_info(SIP_type type)
        : type(type)
        , local_port(0)
    {
    }
    SIP_info(const SIP_info &info) = delete;
    virtual ~SIP_info() {}

    SIP_type type;

    unsigned int local_port;

    trsp_acls acls;

    std::string transportToStr() const override
    {
        if (type == SIP_info::TCP) {
            return "TCP";
        } else if (type == SIP_info::UDP) {
            return "UDP";
        } else if (type == SIP_info::TLS) {
            return "TLS";
        } else if (type == SIP_info::WS) {
            return "WS";
        } else if (type == SIP_info::WSS) {
            return "WSS";
        }

        return "";
    }
};

class SIP_UDP_info : public SIP_info {
  public:
    SIP_UDP_info()
        : SIP_info(UDP)
    {
    }
    SIP_UDP_info(const SIP_UDP_info &info) = delete;
    virtual ~SIP_UDP_info() {}

    static SIP_UDP_info *toSIP_UDP(SIP_info *info)
    {
        if (info->type == UDP) {
            return static_cast<SIP_UDP_info *>(info);
        }
        return 0;
    }
};

class SIP_TCP_info : public SIP_info {
  protected:
    explicit SIP_TCP_info(SIP_info::SIP_type type)
        : SIP_info(type)
        , tcp_connect_timeout(DEFAULT_TCP_CONNECT_TIMEOUT)
        , tcp_idle_timeout(DEFAULT_IDLE_TIMEOUT)
    {
    }

  public:
    SIP_TCP_info()
        : SIP_info(TCP)
        , tcp_connect_timeout(DEFAULT_TCP_CONNECT_TIMEOUT)
        , tcp_idle_timeout(DEFAULT_IDLE_TIMEOUT)
    {
    }
    SIP_TCP_info(const SIP_TCP_info &info) = delete;
    virtual ~SIP_TCP_info() {}

    unsigned int tcp_connect_timeout;
    unsigned int tcp_idle_timeout;

    static SIP_TCP_info *toSIP_TCP(SIP_info *info)
    {
        if (info->type == TCP) {
            return static_cast<SIP_TCP_info *>(info);
        }
        return 0;
    }
};

class SIP_TLS_info : public SIP_TCP_info {
  protected:
    explicit SIP_TLS_info(SIP_info::SIP_type type)
        : SIP_TCP_info(type)
    {
    }

  public:
    SIP_TLS_info()
        : SIP_TCP_info(TLS)
    {
    }
    SIP_TLS_info(const SIP_TLS_info &info) = delete;
    virtual ~SIP_TLS_info() {}

    tls_server_settings server_settings;
    tls_client_settings client_settings;

    static SIP_TLS_info *toSIP_TLS(SIP_info *info)
    {
        if (info->type == TLS || info->type == WSS) {
            return static_cast<SIP_TLS_info *>(info);
        }
        return 0;
    }
};

class WS_info {
  public:
    WS_info()
        : cors_mode(true)
    {
    }
    WS_info(const WS_info &info)
        : cors_mode(info.cors_mode)
    {
    }
    virtual ~WS_info() {}

    bool cors_mode;
};

class SIP_WS_info : public SIP_TCP_info, public WS_info {
  public:
    SIP_WS_info()
        : SIP_TCP_info(WS)
    {
    }
    SIP_WS_info(const SIP_WS_info &info) = delete;
    virtual ~SIP_WS_info() {}

    static SIP_WS_info *toSIP_WS(SIP_info *info)
    {
        if (info->type == WS) {
            return static_cast<SIP_WS_info *>(info);
        }
        return 0;
    }
};

class SIP_WSS_info : public SIP_TLS_info, public WS_info {
  public:
    SIP_WSS_info()
        : SIP_TLS_info(WSS)
    {
    }
    SIP_WSS_info(const SIP_WSS_info &info) = delete;
    virtual ~SIP_WSS_info() {}

    static SIP_WSS_info *toSIP_WSS(SIP_info *info)
    {
        if (info->type == WSS) {
            return static_cast<SIP_WSS_info *>(info);
        }
        return 0;
    }
};

class MEDIA_info : public IP_info {
  public:
    enum MEDIA_type { RTP = 0, RTSP };

    MEDIA_info(MEDIA_type type);
    MEDIA_info(const MEDIA_info &info) = delete;
    MEDIA_info(MEDIA_info &&info)      = delete;
    virtual ~MEDIA_info();

    MEDIA_type     mtype;
    unsigned short low_port;
    unsigned short high_port;

    std::string transportToStr() const override
    {
        if (mtype == MEDIA_info::RTP) {
            return "RTP";
        } else if (mtype == MEDIA_info::RTSP) {
            return "RTSP";
        }

        return "";
    }

    virtual int  prepare(const std::string &iface_name);
    virtual bool getNextRtpAddress(sockaddr_storage &ss)                                                       = 0;
    virtual void freeRtpAddress(const sockaddr_storage &ss)                                                    = 0;
    virtual void iterateUsedPorts(std::function<void(const std::string &, unsigned short, unsigned short)> cl) = 0;

    std::string &getAdvertisedHost()
    {
        static string empty_string;
        if (!public_domain.empty())
            return public_domain;
        if (!public_ip.empty())
            return public_ip;
        return empty_string;
    }
};

class RTP_info : public MEDIA_info {
  private:
    std::list<PortMap> addresses;
    bool               single_address;

  public:
    RTP_info()
        : MEDIA_info(RTP)
    {
    }
    RTP_info(unsigned short low, unsigned short high)
        : RTP_info()
    {
        low_port  = low;
        high_port = high;
        addMediaAddress(std::string());
    }
    RTP_info(const RTP_info &info) = delete;
    virtual ~RTP_info() {}

    static RTP_info *toMEDIA_RTP(MEDIA_info *info)
    {
        if (info->mtype == RTP) {
            return static_cast<RTP_info *>(info);
        }

        return 0;
    }

    void addMediaAddress(const std::string &address);
    int  prepare(const std::string &iface_name) override;
    bool getNextRtpAddress(sockaddr_storage &ss) override;
    void freeRtpAddress(const sockaddr_storage &ss) override;
    void iterateUsedPorts(std::function<void(const std::string &, unsigned short, unsigned short)> cl) override;
};

class RTSP_info : public MEDIA_info {
    PortMap portmap;

  public:
    RTSP_info()
        : MEDIA_info(RTSP)
    {
    }
    RTSP_info(const RTSP_info &info) = delete;
    virtual ~RTSP_info() {}

    int  prepare(const std::string &iface_name);
    bool getNextRtpAddress(sockaddr_storage &ss);
    void freeRtpAddress(const sockaddr_storage &ss);
    void iterateUsedPorts(std::function<void(const std::string &, unsigned short, unsigned short)> cl);

    static RTSP_info *toMEDIA_RTSP(MEDIA_info *info)
    {
        if (info->mtype == RTSP) {
            return static_cast<RTSP_info *>(info);
        }
        return 0;
    }
};

template <typename ProtoInfo> class PI_interface {
  public:
    PI_interface() {}
    PI_interface(const PI_interface<ProtoInfo> &info) = delete;
    PI_interface(PI_interface<ProtoInfo> &&info)      = default;
    virtual ~PI_interface()
    {
        for (auto &info : proto_info) {
            delete info;
        }
    }

    std::string                             name;
    std::vector<ProtoInfo>                  proto_info;
    std::map<unsigned char, unsigned short> local_ip_proto2proto_idx;
};

class SIP_interface : public PI_interface<SIP_info *> {
  public:
    SIP_interface() {}
    SIP_interface(const SIP_interface &sip) = delete;
    SIP_interface(SIP_interface &&sip)      = default;
    virtual ~SIP_interface() {}

    std::string default_media_if;

    int insertProtoMapping(SIP_info &info, unsigned short index)
    {
        unsigned char mask = static_cast<unsigned char>(info.type_ip | (info.type << 3));
        std::map<unsigned char, unsigned short>::iterator it = local_ip_proto2proto_idx.find(mask);
        if (it != local_ip_proto2proto_idx.end()) {
            ERROR("duplicate local signalling protocol %s/%s. replace existent one in the map",
                  proto_info[index]->ipTypeToStr().c_str(), proto_info[index]->transportToStr().c_str());
            local_ip_proto2proto_idx[mask] = index;
        } else {
            local_ip_proto2proto_idx.emplace(mask, index);
        }
        return 0;
    }

    int findProto(AddressType address_type, SIP_info::SIP_type transport_type)
    {
        unsigned char mask    = static_cast<unsigned char>(address_type | (transport_type << 3));
        auto          addr_it = local_ip_proto2proto_idx.find(mask);
        if (addr_it != local_ip_proto2proto_idx.end()) {
            return addr_it->second;
        }
        return -1;
    }
};

class MEDIA_interface : public PI_interface<MEDIA_info *> {
  public:
    struct Secure_credentials {
        dtls_client_settings       client_settings;
        dtls_server_settings       server_settings;
        std::vector<CryptoProfile> profiles;
        std::vector<uint8_t>       zrtp_hashes;
        std::vector<uint8_t>       zrtp_ciphers;
        std::vector<uint8_t>       zrtp_authtags;
        std::vector<uint8_t>       zrtp_dhmodes;
        std::vector<uint8_t>       zrtp_sas;
        bool                       srtp_enable;
        bool                       dtls_enable;
        bool                       zrtp_enable;
        Secure_credentials()
            : srtp_enable(false)
            , dtls_enable(false)
            , zrtp_enable(false)
        {
        }
        Secure_credentials(const Secure_credentials &_if) = delete;
    };
    std::unique_ptr<Secure_credentials> srtp;

    MEDIA_interface()
        : srtp(new Secure_credentials)
    {
    }
    MEDIA_interface(const MEDIA_interface &_if) = delete;
    MEDIA_interface(MEDIA_interface &&info)     = default;

    int zrtp_hash_from_str(const string &str)
    {
#ifdef WITH_ZRTP
        if (str == "S256")
            return ZRTP_HASH_S256;
        if (str == "S384")
            return ZRTP_HASH_S384;
        if (str == "N256")
            return ZRTP_HASH_N256;
        if (str == "N384")
            return ZRTP_HASH_N384;
#endif /*WITH_ZRTP*/
        return 0;
    }

    int zrtp_cipher_from_str(const string &str)
    {
#ifdef WITH_ZRTP
        if (str == "AES1")
            return ZRTP_CIPHER_AES1;
        if (str == "AES2")
            return ZRTP_CIPHER_AES2;
        if (str == "AES3")
            return ZRTP_CIPHER_AES3;
        if (str == "2FS1")
            return ZRTP_CIPHER_2FS1;
        if (str == "2FS2")
            return ZRTP_CIPHER_2FS2;
        if (str == "2FS3")
            return ZRTP_CIPHER_2FS3;
#endif /*WITH_ZRTP*/
        return 0;
    }

    int zrtp_authtag_from_str(const string &str)
    {
#ifdef WITH_ZRTP
        if (str == "HS32")
            return ZRTP_AUTHTAG_HS32;
        if (str == "HS80")
            return ZRTP_AUTHTAG_HS80;
        if (str == "SK32")
            return ZRTP_AUTHTAG_SK32;
        if (str == "SK64")
            return ZRTP_AUTHTAG_SK64;
#endif /*WITH_ZRTP*/
        return 0;
    }

    int zrtp_dhmode_from_str(const string &str)
    {
#ifdef WITH_ZRTP
        if (str == "DH2K")
            return ZRTP_KEYAGREEMENT_DH2k;
        if (str == "EC25")
            return ZRTP_KEYAGREEMENT_EC25;
        if (str == "DH3K")
            return ZRTP_KEYAGREEMENT_DH3k;
        if (str == "EC38")
            return ZRTP_KEYAGREEMENT_EC38;
        if (str == "EC52")
            return ZRTP_KEYAGREEMENT_EC52;
        if (str == "PRSH")
            return ZRTP_KEYAGREEMENT_Prsh;
        if (str == "MULT")
            return ZRTP_KEYAGREEMENT_Mult;
#endif /*WITH_ZRTP*/
        return 0;
    }

    int zrtp_sas_from_str(const string &str)
    {
#ifdef WITH_ZRTP
        if (str == "B32")
            return ZRTP_SAS_B32;
        if (str == "B256")
            return ZRTP_SAS_B256;
#endif /*WITH_ZRTP*/
        return 0;
    }

    int insertProtoMapping(MEDIA_info &info, unsigned short index)
    {
        unsigned char mask = static_cast<unsigned char>(info.type_ip | (info.mtype << 3));
        std::map<unsigned char, unsigned short>::iterator it = local_ip_proto2proto_idx.find(mask);
        if (it != local_ip_proto2proto_idx.end()) {
            ERROR("duplicate local media protocol %s/%s. replace existent one in the map",
                  proto_info[index]->ipTypeToStr().c_str(), proto_info[index]->transportToStr().c_str());
            local_ip_proto2proto_idx[mask] = index;
        } else {
            local_ip_proto2proto_idx.emplace(mask, index);
        }
        return 0;
    }

    int findProto(AddressType address_type, MEDIA_info::MEDIA_type media_type)
    {
        unsigned char mask    = static_cast<unsigned char>(address_type | (media_type << 3));
        auto          addr_it = local_ip_proto2proto_idx.find(mask);
        if (addr_it != local_ip_proto2proto_idx.end()) {
            return addr_it->second;
        }
        return -1;
    }
};

class IPAddr {
    sockaddr_storage saddr;

  public:
    IPAddr(const string &addr, const short family)
        : addr(addr)
        , family(family)
    {
        saddr.ss_family = family;
        am_inet_pton(addr.c_str(), &saddr);
    }

    IPAddr(const IPAddr &ip)
        : addr(ip.addr)
        , family(ip.family)
    {
        memcpy(&saddr, &ip.saddr, sizeof(struct sockaddr_storage));
    }

    bool operator==(const string &ip);

    std::string addr;
    short       family;
};

struct SysIntf {
    std::string       name;
    std::list<IPAddr> addrs;
    // identical to those returned by SIOCGIFFLAGS
    unsigned int flags;
    unsigned int mtu;
};

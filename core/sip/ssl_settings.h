#pragma once

#include <vector>
#include <map>
#include <string>
using std::vector;
using std::map;
using std::string;

struct settings
{
    std::string certificate;
    std::string certificate_key;
    std::vector<std::string> ca_list;

    virtual ~settings();

    bool checkCertificateAndKey(const char *interface_name,
                                const char* interface_type,
                                const char *role_name);
    virtual const char *getProtocolName() = 0;
};

class tls_settings : public settings
{
public:
    virtual ~tls_settings(){}

    enum Protocol {
        TLSv1,
        TLSv1_1,
        TLSv1_2
    };

    static Protocol protocolFromStr(const std::string& proto) {
        if(proto == "TLSv1") {
            return TLSv1;
        } else if(proto == "TLSv1.1") {
            return TLSv1_1;
        }

        return TLSv1_2;
    }

    static  std::string protocolToStr(Protocol proto) {
        if(proto == TLSv1) {
            return "TLSv1";
        } else if(proto == TLSv1_1) {
            return "TLSv1.1";
        }

        return "TLSv1.2";
    }

    virtual const char *getProtocolName();

    std::vector<Protocol> protocols;
};

class dtls_settings : public settings
{
public:
    virtual ~dtls_settings(){}

    enum Protocol {
        DTLSv1,
        DTLSv1_2
    };

    static Protocol protocolFromStr(const std::string& proto) {
        if(proto == "DTLSv1") {
            return DTLSv1;
        } else {
            return DTLSv1_2;
        }
    }

    static  std::string protocolToStr(Protocol proto) {
        if(proto == DTLSv1) {
            return "DTLSv1";
        } else {
            return "DTLSv1.2";
        }
    }

    virtual const char *getProtocolName();

    std::vector<Protocol> protocols;
    std::vector<uint16_t> srtp_profiles;
};

template<class SettingsType>
class ssl_client_settings : public SettingsType
{
public:
    ssl_client_settings()
      : verify_certificate_chain(false),
        verify_certificate_cn(false)
    {}
    ~ssl_client_settings(){}

    bool verify_certificate_chain;
    bool verify_certificate_cn;
};

typedef ssl_client_settings<tls_settings> tls_client_settings;
typedef ssl_client_settings<dtls_settings> dtls_client_settings;

template<class SettingsType>
class ssl_server_settings : public SettingsType
{
public:
    ssl_server_settings()
      : require_client_certificate(false),
        verify_client_certificate(false)
    {}
    ~ssl_server_settings(){}

    bool require_client_certificate;
    bool verify_client_certificate;
    std::vector<std::string> cipher_list;
    std::vector<std::string> macs_list;
    std::string dhparam;
};

typedef ssl_server_settings<tls_settings> tls_server_settings;
typedef ssl_server_settings<dtls_settings> dtls_server_settings;

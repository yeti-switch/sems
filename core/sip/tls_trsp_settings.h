#pragma once

#include <vector>
#include <map>
#include <string>
using std::vector;
using std::map;
using std::string;

class tls_settings
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

    std::vector<Protocol> protocols;
    std::string certificate;
    std::string certificate_key;
    std::vector<std::string> ca_list;
};

class tls_client_settings : public tls_settings
{
public:
    tls_client_settings() : require_client_certificate(false), verify_client_certificate(false){}
    ~tls_client_settings(){}

    std::vector<std::string> cipher_list;
    std::string dhparam;
    bool require_client_certificate;
    bool verify_client_certificate;

};

class tls_server_settings : public tls_settings
{
public:
    tls_server_settings() : verify_certificate_chain(false), verify_certificate_cn(false){}
    ~tls_server_settings(){}

    bool verify_certificate_chain;
    bool verify_certificate_cn;
};

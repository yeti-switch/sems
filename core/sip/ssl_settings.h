#pragma once

#include "AmThread.h"
#include "AmStatistics.h"
#include "AmArg.h"

#include <vector>
#include <map>
#include <string>

#include <botan/x509cert.h>
#include <botan/pkcs8.h>
#include <botan/certstor.h>

class settings {
    AmMutex mutex;

    std::vector<Botan::X509_Certificate> certificates;
    std::unique_ptr<Botan::Private_Key>  certificate_key;
    std::vector<Botan::X509_Certificate> ca_list;

    AtomicCounter *certificate_not_after_counter;

  public:
    string         certificate_path;
    string         certificate_key_path;
    vector<string> ca_path_list;

    settings();

    AtomicCounter &initNotAfterCounter();

    void load_certificates();
    bool checkCertificateAndKey(const char *interface_name, const char *interface_type, const char *role_name);

    std::vector<Botan::X509_Certificate> getCertificateCopy();
    std::string                          getCertificateFingerprint(const std::string &hash_name);
    std::unique_ptr<Botan::Private_Key>  getCertificateKeyCopy();
    vector<Botan::Certificate_Store *>   getCertificateAuthorityCopy();

    virtual const char              *getProtocolName()       = 0;
    virtual std::vector<std::string> getSupportedProtocols() = 0;
};

class tls_settings : public settings {
  public:
    virtual ~tls_settings() {}

    enum Protocol { UNSUPPORT, TLSv1_2, TLSv1_3 };

    static Protocol protocolFromStr(const std::string &proto)
    {
        if (proto == "TLSv1.2") {
            return TLSv1_2;
        } else if (proto == "TLSv1.3") {
            return TLSv1_3;
        }

        return UNSUPPORT;
    }

    static std::string protocolToStr(Protocol proto)
    {
        if (proto == TLSv1_2) {
            return "TLSv1.2";
        } else if (proto == TLSv1_3) {
            return "TLSv1.3";
        }

        return "";
    }

    virtual const char              *getProtocolName();
    virtual std::vector<std::string> getSupportedProtocols();

    std::vector<Protocol> protocols;
};

class dtls_settings : public settings {
  public:
    virtual ~dtls_settings() {}

    enum Protocol { UNSUPPORT, DTLSv1_2 };

    static Protocol protocolFromStr(const std::string &proto)
    {
        if (proto == "DTLSv1.2") {
            return DTLSv1_2;
        }
        return UNSUPPORT;
    }

    static std::string protocolToStr(Protocol proto)
    {
        if (proto == DTLSv1_2) {
            return "DTLSv1.2";
        }
        return "";
    }

    virtual const char              *getProtocolName();
    virtual std::vector<std::string> getSupportedProtocols();

    std::vector<Protocol> protocols;
    std::vector<uint16_t> srtp_profiles;
};

template <class SettingsType> class ssl_client_settings : public SettingsType {
  public:
    ssl_client_settings()
        : verify_certificate_chain(false)
        , verify_certificate_cn(false)
    {
    }
    ~ssl_client_settings() {}

    bool verify_certificate_chain;
    bool verify_certificate_cn;
};

typedef ssl_client_settings<tls_settings>  tls_client_settings;
typedef ssl_client_settings<dtls_settings> dtls_client_settings;

template <class SettingsType> class ssl_server_settings : public SettingsType {
  public:
    ssl_server_settings()
        : require_client_certificate(false)
        , verify_client_certificate(false)
    {
    }
    ~ssl_server_settings() {}

    bool                     require_client_certificate;
    bool                     verify_client_certificate;
    std::vector<std::string> cipher_list;
    std::vector<std::string> macs_list;
    std::string              dhparam;
};

typedef ssl_server_settings<tls_settings>  tls_server_settings;
typedef ssl_server_settings<dtls_settings> dtls_server_settings;

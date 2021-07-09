#pragma once

#include <vector>
#include <map>
#include <string>
#include <AmThread.h>

#include <botan/x509cert.h>
#include <botan/pkcs8.h>

using std::vector;
using std::map;
using std::string;

template<typename T>
class binary_data {
    std::unique_ptr<T> data;
    AmMutex mutex;
public:
    binary_data(){}
    binary_data(const binary_data&) = delete;
    void operator = (const binary_data&) = delete;
    ~binary_data() {}

    void set(T* data_) {
        AmLock lock(mutex);
        data.reset(data_);
    }

    T* get() {
        AmLock lock(mutex);
        return new T(*data.get());
    }

    void clear() {
        AmLock lock(mutex);
        if(data.get()) {
            delete data.release();
        }
    }
};

template<>Botan::Private_Key* binary_data<Botan::Private_Key>::get();
extern template Botan::Private_Key* binary_data<Botan::Private_Key>::get();

//------------
//TODO(): fix crash, but created memory leaks
// template<>binary_data<Botan::Private_Key>::~binary_data();
// extern template binary_data<Botan::Private_Key>::~binary_data();
//------------

typedef binary_data<Botan::X509_Certificate> Certificate;
typedef binary_data<Botan::Private_Key> PrivateKey;

template<typename T>
class binary_list 
{
    vector<T> data_;
    AmMutex mutex;

    friend struct settings;
    operator vector<T>& () { return data_; }
    void clear() { data_.clear(); }
public:
    binary_list(){}
    operator AmMutex& () { return mutex; }
    vector<T> data() { AmLock lock(mutex); return data_; }
};
struct settings
{
    string certificate_path;
    string certificate_key_path;
    vector<string> ca_path_list;

    Certificate certificate;
    PrivateKey certificate_key;
    binary_list<Botan::X509_Certificate> ca_list;

    settings(){}
    virtual ~settings(){}

    void load_certificates();
    bool checkCertificateAndKey(const char *interface_name,
                                const char* interface_type,
                                const char *role_name);

    void dump(const std::string& prefix);
    virtual const char *getProtocolName() = 0;
    virtual std::vector<std::string> getSupportedProtocols() = 0;
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
    virtual std::vector<std::string> getSupportedProtocols();

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
    virtual std::vector<std::string> getSupportedProtocols();

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

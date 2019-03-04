#ifndef AM_SRTP_CONNECTION_H
#define AM_SRTP_CONNECTION_H

#include "sip/ssl_settings.h"
#include "singleton.h"

#include <botan/auto_rng.h>
#include <botan/tls_policy.h>
#include <botan/tls_channel.h>
#include <botan/tls_callbacks.h>
#include <botan/credentials_manager.h>

#include <srtp.h>

#include <memory>
using std::auto_ptr;

class AmRtpStream;

#define SRTP_KEY_SIZE 30

#define SRTP_PACKET_PARSE_ERROR -1
#define SRTP_PACKET_PARSE_OK 0
#define SRTP_PACKET_PARSE_RTP 1

class dtls_conf : public Botan::TLS::Policy, public Botan::Credentials_Manager
{
    friend class AmSrtpConnection;
    dtls_client_settings* s_client;
    dtls_server_settings* s_server;
    Botan::X509_Certificate certificate;
    std::unique_ptr<Botan::Private_Key> key;

    //for optional client connection
    bool is_optional;
    std::string cipher;
    std::string mac;
    std::string sig;
public:
    dtls_conf();
    dtls_conf(dtls_client_settings* settings);
    dtls_conf(dtls_server_settings* settings);
    dtls_conf(const dtls_conf& conf);
    void operator=(const dtls_conf& conf);

    //Policy functions
    vector<string> allowed_key_exchange_methods() const override;
    vector<string> allowed_signature_methods() const override;
    vector<string> allowed_ciphers() const override;
    vector<string> allowed_macs() const override;
    bool allow_tls10()  const override { return false;}
    bool allow_tls11()  const override { return false;}
    bool allow_tls12()  const override { return false;}
    bool allow_dtls10() const override;
    bool allow_dtls12() const override;
    bool require_cert_revocation_info() const override { return false; }
    std::vector<uint16_t> srtp_profiles() const override;

    //Credentials_Manager functions
    vector<Botan::Certificate_Store*> trusted_certificate_authorities(const string& type, const string& context) override;
    vector<Botan::X509_Certificate> cert_chain(const vector<string>& cert_key_types, const string& type, const string& context) override;
    Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert, const string& type, const string& context) override;

    void set_optional_parameters(std::string sig_, std::string cipher_, std::string mac_);
};

class dtls_rand_generator
{
public:
    Botan::AutoSeeded_RNG rng;
    operator Botan::RandomNumberGenerator& () {
        return rng;
    }
};

typedef singleton<dtls_rand_generator> rand_generator_dtls;

class dtls_session_manager
{
public:
    Botan::TLS::Session_Manager_In_Memory ssm;
    dtls_session_manager() : ssm(*rand_generator_dtls::instance()){}
    operator Botan::TLS::Session_Manager_In_Memory& () {
        return ssm;
    }
};

typedef singleton<dtls_session_manager> session_manager_dtls;

class srtp_master_key_p
{
public:
    srtp_master_key_p(srtp_master_key_t key)
        : master_key(key){}
    ~srtp_master_key_p();

    operator srtp_master_key_t*()
    {
        return &master_key;
    }

    srtp_master_key_t master_key;
};

class srtp_fingerprint_p
{
public:
    bool is_use;
    std::string hash;
    std::string value;
    
    srtp_fingerprint_p()
    : is_use(false){}
    srtp_fingerprint_p(const std::string& hash_, const std::string& value_)
    : is_use(value_.size() &&  hash_.size()), hash(hash_),value(value_){}
    srtp_fingerprint_p(const srtp_fingerprint_p& fa)
    : is_use(fa.is_use), hash(fa.hash),value(fa.value){}
    
    void operator=(const srtp_fingerprint_p& fa) {
        is_use = fa.is_use;
        hash = fa.hash;
        value = fa.value;
    }
};

class AmSrtpConnection : public Botan::TLS::Callbacks
{
public:
    enum RTP_mode
    {
        RTP_DEFAULT,
        DTLS_SRTP_SERVER,
        DTLS_SRTP_CLIENT,
        SRTP_EXTERNAL_KEY
    };
private:
    typedef std::vector<srtp_master_key_p> srtp_master_keys;
    RTP_mode       rtp_mode;
    unsigned char  c_key_s[SRTP_KEY_SIZE];
    unsigned char  c_key_r[SRTP_KEY_SIZE];
    bool b_init[2];
    srtp_profile_t srtp_profile;
    srtp_fingerprint_p fingerprint;
    srtp_t srtp_s_session;
    srtp_t srtp_r_session;

    Botan::TLS::Channel* dtls_channel;
    AmRtpStream* rtp_stream;
    auto_ptr<dtls_conf> dtls_settings;
    bool b_srtcp;
protected:
    void create_dtls();
    bool isRtpPacket(uint8_t* data, unsigned int size);
public:
    AmSrtpConnection(AmRtpStream* stream, bool srtcp);
    ~AmSrtpConnection();

    RTP_mode get_rtp_mode() { return rtp_mode; }
    void use_dtls(dtls_client_settings* settings, const srtp_fingerprint_p& fingerprint);
    void use_dtls(dtls_server_settings* settings, const srtp_fingerprint_p& fingerprint);
    void use_key(srtp_profile_t profile, unsigned char* key_s, unsigned int key_s_len, unsigned char* key_r, unsigned int key_r_len);

    static void base64_key(const std::string& key, unsigned char* key_s, unsigned int& key_s_len);
    static std::string gen_base64_key(srtp_profile_t profile);
    static srtp_fingerprint_p gen_fingerprint(class dtls_settings* settings);

    int on_data_recv(uint8_t* data, unsigned int* size, bool rtcp);
    bool on_data_send(uint8_t* data, unsigned int* size, bool rtcp);

    void tls_emit_data(const uint8_t data[], size_t size);
    void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size);
    void tls_alert(Botan::TLS::Alert alert);
    bool tls_session_established(const Botan::TLS::Session& session);
    void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>& cert_chain,
                                const std::vector<std::shared_ptr<const Botan::OCSP::Response>>& ocsp_responses,
                                const std::vector<Botan::Certificate_Store*>& trusted_roots,
                                Botan::Usage_Type usage,
                                const std::string& hostname,
                                const Botan::TLS::Policy& policy);
    virtual void tls_session_activated();
};

#endif/*AM_SRTP_CONNECTION_H*/

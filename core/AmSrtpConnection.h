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

#define SRTP_KEY_SIZE 32
#define MKI_SIZE      16

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
    RTP_mode       rtp_mode;
    unsigned char  c_key[SRTP_KEY_SIZE];
    srtp_master_key_t mkey;
    unsigned char mki_id;

    Botan::TLS::Channel* dtls_channel;
    AmRtpStream* rtp_stream;
    auto_ptr<dtls_conf> dtls_settings;
    srtp_t srtp_session;
    srtp_policy_t srtp_policy;
protected:
    void create_dtls();
public:
    AmSrtpConnection(AmRtpStream* stream);
    ~AmSrtpConnection();

    RTP_mode get_rtp_mode() { return rtp_mode; }
    void use_dtls(dtls_client_settings* settings);
    void use_dtls(dtls_server_settings* settings);
    void use_key(srtp_profile_t profile, unsigned char* key, unsigned int key_len);

    void on_data_recv(uint8_t* data, size_t size);
    void on_data_send(uint8_t* data, size_t size);

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
};

#endif/*AM_SRTP_CONNECTION_H*/

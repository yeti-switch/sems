#ifndef AM_DTLS_CONNECTION_H
#define AM_DTLS_CONNECTION_H

#include "AmRtpConnection.h"

#include "sip/ssl_settings.h"
#include "singleton.h"

#include <memory>
using std::auto_ptr;
using std::unique_ptr;
using std::shared_ptr;

#include <botan/auto_rng.h>
#include <botan/tls_policy.h>
#include <botan/tls_channel.h>
#include <botan/tls_callbacks.h>
#include <botan/credentials_manager.h>

#include <srtp.h>

class dtls_conf : public Botan::TLS::Policy, public Botan::Credentials_Manager
{
    friend class AmSrtpConnection;
    friend class AmDtlsConnection;
    dtls_client_settings* s_client;
    dtls_server_settings* s_server;
    Botan::X509_Certificate certificate;
    unique_ptr<Botan::Private_Key> key;

    //for optional client connection
    bool is_optional;
    string cipher;
    string mac;
    string sig;
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
    vector<uint16_t> srtp_profiles() const override;

    //Credentials_Manager functions
    vector<Botan::Certificate_Store*> trusted_certificate_authorities(const string& type, const string& context) override;
    vector<Botan::X509_Certificate> cert_chain(const vector<string>& cert_key_types, const string& type, const string& context) override;
    Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert, const string& type, const string& context) override;

    void set_optional_parameters(string sig_, string cipher_, string mac_);
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

class srtp_fingerprint_p
{
public:
    bool is_use;
    string hash;
    string value;

    srtp_fingerprint_p()
    : is_use(false){}
    srtp_fingerprint_p(const string& hash_, const string& value_)
    : is_use(value_.size() &&  hash_.size()), hash(hash_),value(value_){}
    srtp_fingerprint_p(const srtp_fingerprint_p& fa)
    : is_use(fa.is_use), hash(fa.hash),value(fa.value){}

    void operator=(const srtp_fingerprint_p& fa) {
        is_use = fa.is_use;
        hash = fa.hash;
        value = fa.value;
    }
};

class AmDtlsConnection : public AmStreamConnection, public Botan::TLS::Callbacks
{
    Botan::TLS::Channel* dtls_channel;
    auto_ptr<dtls_conf> dtls_settings;
    srtp_fingerprint_p fingerprint;
    srtp_profile_t srtp_profile;
    dtls_rand_generator rand_gen;
public:
    AmDtlsConnection(AmRtpTransport* transport, const string& remote_addr, int remote_port, const srtp_fingerprint_p& _fingerprint, bool client);
    virtual ~AmDtlsConnection();

    static srtp_fingerprint_p gen_fingerprint(class dtls_settings* settings);

    void handleConnection(uint8_t * data, unsigned int size, struct sockaddr_storage * recv_addr, struct timeval recv_time) override;

    void tls_emit_data(const uint8_t data[], size_t size) override;
    void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override;
    void tls_alert(Botan::TLS::Alert alert) override;
    bool tls_session_established(const Botan::TLS::Session& session) override;
    void tls_verify_cert_chain(const vector<Botan::X509_Certificate>& cert_chain,
                                const vector<shared_ptr<const Botan::OCSP::Response>>& ocsp_responses,
                                const vector<Botan::Certificate_Store*>& trusted_roots,
                                Botan::Usage_Type usage,
                                const string& hostname,
                                const Botan::TLS::Policy& policy) override;
    void tls_session_activated() override;
};

#endif/*AM_DTLS_CONNECTION_H*/

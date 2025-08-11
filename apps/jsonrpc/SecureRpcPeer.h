#ifndef SECURE_RPC_PEER_H
#define SECURE_RPC_PEER_H

#include "WsRpcPeer.h"
#include "sip/ssl_settings.h"

#include <botan/system_rng.h>
#include <botan/tls_policy.h>
#include <botan/tls_channel.h>
#include <botan/tls_callbacks.h>
#include <botan/credentials_manager.h>
#include <botan/tls_session_manager_memory.h>
#include <BotanHelpers.h>

#define MAX_TLS_SESSIONS 8192

class tls_rpc_conf : public Botan::TLS::Policy, public Botan::Credentials_Manager {
    friend class SecureRpcPeer;

    tls_client_settings                 *s_client;
    tls_server_settings                 *s_server;
    std::vector<Botan::X509_Certificate> certificates;
    std::shared_ptr<Botan::Private_Key>  key;

    // ciphersuite policy overrides
    bool        policy_override;
    std::string cipher;
    std::string mac;
    std::string sig;

  public:
    tls_rpc_conf(tls_settings *settings);
    tls_rpc_conf(const tls_rpc_conf &conf);

    void operator=(const tls_rpc_conf &conf);

    // Policy functions
    vector<string> allowed_key_exchange_methods() const override;
    vector<string> allowed_signature_methods() const override;
    vector<string> allowed_ciphers() const override;
    vector<string> allowed_macs() const override;
    size_t         minimum_rsa_bits() const override;
    bool           allow_tls12() const override;
    bool           allow_dtls12() const override { return false; }
    bool           require_cert_revocation_info() const override { return false; }
    bool           require_client_certificate_authentication() const override;

    // Credentials_Manager functions
    vector<Botan::Certificate_Store *>  trusted_certificate_authorities(const string &type,
                                                                        const string &context) override;
    vector<Botan::X509_Certificate>     cert_chain(const std::vector<std::string>                &cert_key_types,
                                                   const std::vector<Botan::AlgorithmIdentifier> &cert_signature_schemes,
                                                   const std::string &type, const std::string &context) override;
    std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate &cert, const string &type,
                                                        const string &context) override;

    void set_policy_overrides(std::string sig_, std::string cipher_, std::string mac_);
};

class tls_session_manager {
  public:
    std::shared_ptr<Botan::RandomNumberGenerator>          rng;
    std::shared_ptr<Botan::TLS::Session_Manager_In_Memory> ssm;

    tls_session_manager()
        : rng(std::make_shared<Botan::System_RNG>())
        , ssm(std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng, MAX_TLS_SESSIONS))
    {
    }

    void dispose() {}
};

typedef singleton<tls_session_manager> session_manager_tls;

class SecureRpcPeer : public WsRpcPeer, public Botan::TLS::Callbacks {
    std::shared_ptr<tls_rpc_conf>            settings;
    shared_ptr<BotanTLSCallbacksProxy>       tls_callbacks;
    shared_ptr<Botan::RandomNumberGenerator> rand_gen;

    bool                 is_tls;
    bool                 tls_connected;
    Botan::TLS::Channel *tls_channel;

    vector<char> tls_resv_buffer;
    vector<char> tls_send_buffer;

    void initTls(bool server);
    int  ws_recv_data(uint8_t *data, size_t len) override;
    int  ws_send_data(const uint8_t *data, size_t len) override;

  protected:
    void tls_emit_data(std::span<const uint8_t> data) override;
    void tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) override;
    void tls_alert(Botan::TLS::Alert alert) override;
    void tls_session_established(const Botan::TLS::Session_Summary &session) override;
    void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>              &cert_chain,
                               const std::vector<std::optional<Botan::OCSP::Response>> &ocsp_responses,
                               const std::vector<Botan::Certificate_Store *> &trusted_roots, Botan::Usage_Type usage,
                               std::string_view hostname, const Botan::TLS::Policy &policy) override;

  public:
    SecureRpcPeer(const std::string &id);
    ~SecureRpcPeer();

    int connect(const std::string &host, int port, std::string &res_str) override;

    int read_data(char *data, int size) override;
    int netstringsRead() override;

    int send_data(char *data, int size) override;
    int netstringsBlockingWrite() override;

    void addMessage(const char *data, size_t len) override;
    void clearMessage() override;
};

#endif /*SECURE_RPC_PEER_H*/

#ifndef SECURE_RPC_PEER_H
#define SECURE_RPC_PEER_H

#include "WsRpcPeer.h"
#include "sip/ssl_settings.h"

#include <botan/auto_rng.h>
#include <botan/tls_policy.h>
#include <botan/tls_channel.h>
#include <botan/tls_callbacks.h>
#include <botan/credentials_manager.h>

class tls_rpc_conf : public Botan::TLS::Policy, public Botan::Credentials_Manager
{
    friend class SecureRpcPeer;
    tls_client_settings* s_client;
    tls_server_settings* s_server;
    std::vector<Botan::X509_Certificate> certificates;
    std::unique_ptr<Botan::Private_Key> key;

    //ciphersuite policy overrides
    bool policy_override;
    std::string cipher;
    std::string mac;
    std::string sig;
public:
    tls_rpc_conf(tls_settings* settings);
    tls_rpc_conf(const tls_rpc_conf& conf);

    void operator=(const tls_rpc_conf& conf);

    //Policy functions
    vector<string> allowed_key_exchange_methods() const override;
    vector<string> allowed_signature_methods() const override;
    vector<string> allowed_ciphers() const override;
    vector<string> allowed_macs() const override;
    size_t minimum_rsa_bits() const override;
    bool allow_tls10()  const override;
    bool allow_tls11()  const override;
    bool allow_tls12()  const override;
    bool allow_dtls10() const override { return false;}
    bool allow_dtls12() const override { return false;}
    bool require_cert_revocation_info() const override { return false; }
    bool require_client_certificate_authentication() const override;

    //Credentials_Manager functions
    vector<Botan::Certificate_Store*> trusted_certificate_authorities(const string& type, const string& context) override;
    vector<Botan::X509_Certificate> cert_chain(const vector<string>& cert_key_types, const string& type, const string& context) override;
    Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert, const string& type, const string& context) override;

    void set_policy_overrides(std::string sig_, std::string cipher_, std::string mac_);
};

class tls_rand_generator
{
public:
    Botan::AutoSeeded_RNG rng;
    operator Botan::RandomNumberGenerator& () {
        return rng;
    }

    void dispose(){}
};

class tls_session_manager
{
    tls_rand_generator rand_tls;
public:
    Botan::TLS::Session_Manager_In_Memory ssm;
    tls_session_manager() : ssm(rand_tls){}
    operator Botan::TLS::Session_Manager_In_Memory& () {
        return ssm;
    }

    void dispose(){}
};

typedef singleton<tls_session_manager> session_manager_tls;

class SecureRpcPeer : public WsRpcPeer, public Botan::TLS::Callbacks
{
    bool tls_connected;
    bool is_tls;
    tls_rand_generator rand_gen;
    Botan::TLS::Channel* tls_channel;
    tls_rpc_conf*  settings;
    vector<char>   tls_resv_buffer;
    vector<char>   tls_send_buffer;

    void initTls(bool server);
    int ws_recv_data(uint8_t *data, size_t len) override;
    int ws_send_data(const uint8_t* data, size_t len) override;
protected:
    void tls_emit_data(const uint8_t data[], size_t size) override;
    void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override;
    void tls_alert(Botan::TLS::Alert alert) override;
    bool tls_session_established(const Botan::TLS::Session& session) override;
    void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>& cert_chain,
                                const std::vector<std::shared_ptr<const Botan::OCSP::Response>>& ocsp_responses,
                                const std::vector<Botan::Certificate_Store*>& trusted_roots,
                                Botan::Usage_Type usage,
                                const std::string& hostname,
                                const Botan::TLS::Policy& policy) override;
public:
    SecureRpcPeer(const std::string& id);
    ~SecureRpcPeer();

    int connect(const std::string & host, int port, std::string & res_str) override;

    int read_data(char* data, int size) override;
    int netstringsRead() override;

    int send_data(char* data, int size) override;
    int netstringsBlockingWrite() override;

    void addMessage(const char* data, size_t len) override;
    void clearMessage() override;
};

#endif/*SECURE_RPC_PEER_H*/

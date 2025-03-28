#ifndef AM_DTLS_CONNECTION_H
#define AM_DTLS_CONNECTION_H

#include "AmRtpConnection.h"

#include "sip/ssl_settings.h"
#include "sip/wheeltimer.h"
#include "singleton.h"

#include <memory>
using std::unique_ptr;
using std::shared_ptr;
#include <atomic>

#include <botan/system_rng.h>
#include <botan/tls_policy.h>
#include <botan/tls_channel.h>
#include <botan/tls_callbacks.h>
#include <botan/credentials_manager.h>
#include <botan/tls_session_manager_memory.h>
#include <BotanHelpers.h>

#include <srtp/srtp.h>

#define MAX_DTLS_SESSIONS 8192

class dtls_conf : public Botan::TLS::Policy, public Botan::Credentials_Manager
{
    friend class AmSrtpConnection;
    friend class RtpSecureContext;
    dtls_client_settings* s_client;
    dtls_server_settings* s_server;
    vector<Botan::X509_Certificate> certificates;
    shared_ptr<Botan::Private_Key> key;

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
    bool is_client();

    //Policy functions
    bool allow_ssl_key_log_file() const override{ return true; }
    vector<string> allowed_key_exchange_methods() const override;
    vector<string> allowed_signature_methods() const override;
    vector<string> allowed_ciphers() const override;
    vector<string> allowed_macs() const override;
    bool allow_tls12()  const override { return false;}
    bool allow_dtls12() const override;
    bool require_cert_revocation_info() const override { return false; }
    bool require_client_certificate_authentication() const override { return true; }
    vector<uint16_t> srtp_profiles() const override;

    //Credentials_Manager functions
    vector<Botan::Certificate_Store*> trusted_certificate_authorities(
        const string& type,
        const string& context) override;

    vector<Botan::X509_Certificate> cert_chain(
        const vector<string>& cert_key_types,
        const std::vector<Botan::AlgorithmIdentifier>& cert_signature_schemes,
        const string& type,
        const string& context) override;
    
    std::shared_ptr<Botan::Private_Key> private_key_for(
        const Botan::X509_Certificate& cert,
        const string& type,
        const string& context) override;

    void set_optional_parameters(string sig_, string cipher_, string mac_);
};

class dtls_session_manager
{
    std::shared_ptr<Botan::RandomNumberGenerator> rng;
  public:
    std::shared_ptr<Botan::TLS::Session_Manager_In_Memory> ssm;
    dtls_session_manager()
      : rng(std::make_shared<Botan::System_RNG>()),
        ssm(std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng, MAX_DTLS_SESSIONS))
    {}
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

struct DtlsContext;
class AmDtlsConnection;
class AmRtpStream;

class DtlsTimer
  : public timer,
    public atomic_ref_cnt
{
    DtlsContext* context;
    AmMutex v_mut;
    bool is_valid;
  public:
    DtlsTimer(DtlsContext* context);
    ~DtlsTimer();
    void fire() override;
    void invalidate();
  private:
    void reset();
};

struct DtlsContext
{
    bool is_client;
    DtlsContext(bool client) : is_client(client){}
    virtual ~DtlsContext(){}

    static srtp_fingerprint_p gen_fingerprint(class dtls_settings* settings);
    virtual void initContext(const string& host, int port, shared_ptr<dtls_conf> settings, bool reinit = false) noexcept(false) = 0;
    virtual void setCurrentConnection(AmDtlsConnection* conn) noexcept(false) = 0;
    virtual bool onRecvData(AmDtlsConnection* conn, uint8_t * data, unsigned int size) noexcept(false) = 0;
    virtual bool timer_check() = 0;
    virtual bool sendData(const uint8_t * data, unsigned int size) noexcept(false) = 0;
    virtual bool getDtlsKeysMaterial(srtp_profile_t& srtp_profile, vector<uint8_t>& local_key, vector<uint8_t>& remote_key) = 0;
    virtual bool isInited() = 0;
    virtual bool isActivated() = 0;
};

class RtpSecureContext : public Botan::TLS::Callbacks, public DtlsContext
{
    shared_ptr<BotanTLSCallbacksProxy> tls_callbacks_proxy;

    srtp_profile_t srtp_profile;
    vector<uint8_t> local_key, remote_key;
    AmMutex channelMutex;
    Botan::TLS::Channel* dtls_channel;
    shared_ptr<dtls_conf> dtls_settings;
    srtp_fingerprint_p fingerprint;
    std::shared_ptr<Botan::RandomNumberGenerator> rand_gen;
    bool activated;

    DtlsTimer *pending_handshake_timer;

    AmRtpStream* rtp_stream;
    AmDtlsConnection* cur_conn;
public:
    RtpSecureContext(AmRtpStream* stream, const srtp_fingerprint_p& _fingerprint, bool client);
    ~RtpSecureContext() noexcept;

    void initContext(const string& host, int port, shared_ptr<dtls_conf> settings, bool reinit = false) noexcept(false) override;
    bool onRecvData(AmDtlsConnection* conn, uint8_t * data, unsigned int size) noexcept(false) override;
    bool timer_check() override;
    bool sendData(const uint8_t * data, unsigned int size) noexcept(false) override;
    void setCurrentConnection(AmDtlsConnection* conn) noexcept(false) override { cur_conn = conn; }
    bool getDtlsKeysMaterial(srtp_profile_t& srtp_profile, vector<uint8_t>& local_key, vector<uint8_t>& remote_key) override;
    bool isInited() override;
    bool isActivated() override;

    //TODO: move methods to the separate class and remove AmDtlsConnectionTLSCallbacksProxy
    void tls_emit_data(std::span<const uint8_t> data) override;
    void tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) override;
    void tls_alert(Botan::TLS::Alert alert) override;
    void tls_session_established(const Botan::TLS::Session_Summary& session) override;
    void tls_verify_cert_chain(
        const std::vector<Botan::X509_Certificate>& cert_chain,
        const std::vector<std::optional<Botan::OCSP::Response>>& ocsp_responses,
        const std::vector<Botan::Certificate_Store*>& trusted_roots,
        Botan::Usage_Type usage,
        std::string_view hostname,
        const Botan::TLS::Policy& policy) override;
    void tls_session_activated() override;
    void tls_ssl_key_log_data(std::string_view label,
                              std::span<const uint8_t> client_random,
                              std::span<const uint8_t> secret) const override;
};

class AmDtlsConnection
  : public AmStreamConnection
{
    DtlsContext* dtls_context;
protected:
    friend class RtpSecureContext;
    ssize_t send(uint8_t * data, unsigned int size);
    void onRecvData(uint8_t * data, unsigned int size);
public:
    AmDtlsConnection(
        AmMediaTransport* transport,
        const string& remote_addr, int remote_port,
        DtlsContext* context);
    virtual ~AmDtlsConnection();

    void handleConnection(
        uint8_t * data, unsigned int size,
        struct sockaddr_storage * recv_addr,
        struct timeval recv_time) override;
    void handleSymmetricRtp(struct sockaddr_storage*, struct timeval*) override;
    ssize_t send(AmRtpPacket * packet) override;
    void getInfo(AmArg& ret) override;
};

#endif/*AM_DTLS_CONNECTION_H*/

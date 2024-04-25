#pragma once

#include <botan/tls_callbacks.h>
#include <botan/hex.h>
#include "sip/ssl_key_logger.h"

class BotanTLSCallbacksProxy
    : public Botan::TLS::Callbacks
{
    Botan::TLS::Callbacks &parent;

  public:
    BotanTLSCallbacksProxy(Botan::TLS::Callbacks &parent)
        : parent(parent)
    {}

    void tls_emit_data(std::span<const uint8_t> data) override
    {
        parent.tls_emit_data(data);
    }

    void tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) override
    {
        parent.tls_record_received(seq_no, data);
    }

    void tls_alert(Botan::TLS::Alert alert) override
    {
        parent.tls_alert(alert);
    }

    void tls_session_established(const Botan::TLS::Session_Summary& session) override
    {
        parent.tls_session_established(session);
    }

    void tls_verify_cert_chain(
        const std::vector<Botan::X509_Certificate>& cert_chain,
        const std::vector<std::optional<Botan::OCSP::Response>>& ocsp_responses,
        const std::vector<Botan::Certificate_Store*>& trusted_roots,
        Botan::Usage_Type usage,
        std::string_view hostname,
        const Botan::TLS::Policy& policy) override
    {
        parent.tls_verify_cert_chain(
            cert_chain,
            ocsp_responses,
            trusted_roots,
            usage,
            hostname,
            policy);
    }

    void tls_session_activated() override
    {
        parent.tls_session_activated();
    }
    
    void tls_ssl_key_log_data(const char* label,
                              const std::vector<uint8_t>& client_random,
                              const Botan::secure_vector<uint8_t>& secret) override
    {
        ssl_key_logger()->log(label,
                            Botan::hex_encode(client_random.data(), client_random.size()),
                            Botan::hex_encode(secret.data(), secret.size()));
    }
};

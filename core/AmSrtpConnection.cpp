#include "AmSrtpConnection.h"
#include "AmRtpStream.h"

#include <botan/tls_client.h>
#include <botan/tls_server.h>
#include <botan/pkcs8.h>
#include <botan/dl_group.h>

dtls_conf::dtls_conf()
: s_client(0), s_server(0)
, is_optional(false)
, certificate(0)
{
}

dtls_conf::dtls_conf(dtls_client_settings* settings)
: s_client(settings), s_server(0)
, certificate(settings->certificate)
, key(Botan::PKCS8::load_key(settings->certificate_key, *rand_generator_dtls::instance()))
, is_optional(false)
{
}

dtls_conf::dtls_conf(dtls_server_settings* settings)
: s_client(0), s_server(settings)
, certificate(settings->certificate)
, key(Botan::PKCS8::load_key(settings->certificate_key, *rand_generator_dtls::instance()))
, is_optional(false)
{
}

dtls_conf::dtls_conf(const dtls_conf& conf)
: s_client(conf.s_client), s_server(conf.s_server)
, certificate(conf.certificate)
, is_optional(conf.is_optional)
{
    if(conf.s_server) {
        key = std::unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(conf.s_server->certificate_key, *rand_generator_dtls::instance()));
    } else if(conf.s_client) {
        key = std::unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(conf.s_client->certificate_key, *rand_generator_dtls::instance()));
    }
}

void dtls_conf::operator=(const dtls_conf& conf)
{
    s_client = conf.s_client;
    s_server = conf.s_server;
    certificate = conf.certificate;
    is_optional = conf.is_optional;
    if(conf.s_server) {
        key = std::unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(conf.s_server->certificate_key, *rand_generator_dtls::instance()));
    } else if(conf.s_client) {
        key = std::unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(conf.s_client->certificate_key, *rand_generator_dtls::instance()));
    }
}

vector<string> dtls_conf::allowed_key_exchange_methods() const
{
    if(s_client && is_optional) {
        return {sig };
    } else {
        return Policy::allowed_key_exchange_methods();
    }
}

vector<string> dtls_conf::allowed_signature_methods() const
{
    if(s_client && is_optional) {
        return {"IMPLICIT"};
    } else {
        return Policy::allowed_signature_methods();
    }
}

vector<string> dtls_conf::allowed_ciphers() const
{
    if(s_server) {
        return s_server->cipher_list;
    } else if(s_client && is_optional) {
        return { cipher };
    } else if(s_client) {
        return Policy::allowed_ciphers();
    }
    ERROR("allowed_ciphers: called in unexpected context");
    return vector<string>();
}

vector<string> dtls_conf::allowed_macs() const
{
    if(s_server) {
        return s_server->macs_list;
    } else if(s_client && is_optional) {
        return {mac };
    } else if(s_client) {
        return Policy::allowed_macs();
    }
    ERROR("allowed_ciphers: called in unexpected context");
    return vector<string>();
}

bool dtls_conf::allow_dtls10()  const
{
    dtls_settings* settings = 0;
    if(s_client) {
        settings = s_client;
    } else if(s_server) {
        settings = s_server;
    }

    if(!settings) {
        ERROR("incorrect pointer");
        return false;
    }

    for(auto& proto : settings->protocols) {
        if(proto == dtls_client_settings::DTLSv1) {
            return true;
        }
    }

    return false;
}

bool dtls_conf::allow_dtls12()  const
{
    dtls_settings* settings = 0;
    if(s_client) {
        settings = s_client;
    } else if(s_server) {
        settings = s_server;
    }

    if(!settings) {
        ERROR("incorrect pointer");
        return false;
    }

    for(auto& proto : settings->protocols) {
        if(proto == dtls_client_settings::DTLSv1_2) {
            return true;
        }
    }

    return false;
}

vector<Botan::Certificate_Store*> dtls_conf::trusted_certificate_authorities(const string& type, const string& context)
{
    dtls_settings* settings = 0;
    if(s_client) {
        settings = s_client;
    } else if(s_server) {
        settings = s_server;
    }

    if(!settings) {
        ERROR("incorrect pointer");
        return std::vector<Botan::Certificate_Store*>();
    }

    vector<Botan::Certificate_Store*> ca;
    for(auto& cert : settings->ca_list) {
        ca.push_back(new Botan::Certificate_Store_In_Memory(Botan::X509_Certificate(cert)));
    }

    if(s_server && !s_server->require_client_certificate) {
        return std::vector<Botan::Certificate_Store*>();
    } else {
        return ca;
    }
}

vector<Botan::X509_Certificate> dtls_conf::cert_chain(const vector<string>& cert_key_types, const string& type, const string& context)
{
    vector<Botan::X509_Certificate> certs;
    std::string algorithm = certificate.load_subject_public_key()->algo_name();
    for(auto& key : cert_key_types) {
        if(algorithm == key) {
            INFO("loaded certificate with algorithm %s", algorithm.c_str());
            certs.push_back(certificate);
        }
    }

    if(certs.empty()) {
        for(auto& key : cert_key_types) {
            WARN("nothing certificates for algorithms %s", key.c_str());
        }
    }
    return certs;
}

Botan::Private_Key* dtls_conf::private_key_for(const Botan::X509_Certificate& cert, const string& type, const string& context)
{
    if(key) {
        return &*key;
    }
    return nullptr;
}

void dtls_conf::set_optional_parameters(std::string sig_, std::string cipher_, std::string mac_)
{
    is_optional = true;
    cipher = cipher_;
    mac = mac_;
    sig = sig_;
}

AmSrtpConnection::AmSrtpConnection(AmRtpStream* stream)
: rtp_mode(RTP_DEFAULT), rtp_stream(stream), dtls_channel(0)
{
}

AmSrtpConnection::~AmSrtpConnection()
{
    if(dtls_channel) {
        delete dtls_channel;
    }
}

void AmSrtpConnection::use_dtls(bool dtls_server, dtls_conf settings)
{
    rtp_mode = (dtls_server ? DTLS_SRTP_SERVER : DTLS_SRTP_CLIENT);
    srtp_settings = settings;

    try {
        if(!dtls_server) {
            dtls_channel = new Botan::TLS::Client(*this, *session_manager_dtls::instance(), settings, settings,*rand_generator_dtls::instance(),
                                                Botan::TLS::Server_Information(rtp_stream->getRHost().c_str(), rtp_stream->getRPort()),
                                                Botan::TLS::Protocol_Version::DTLS_V12);
        } else {
            dtls_channel = new Botan::TLS::Server(*this, *session_manager_dtls::instance(), settings, settings,*rand_generator_dtls::instance(), false);
        }
    } catch(Botan::Exception& exc) {
      ERROR("unforseen error in dtls:%s",
                      exc.what());
      dtls_channel = 0;
    }
}

void AmSrtpConnection::use_sdp(unsigned char* key_own, unsigned int key_own_len,
            unsigned char* key_other, unsigned int key_other_len)
{
    if(key_own_len < SRTP_KEY_SIZE ||
        key_other_len < SRTP_KEY_SIZE) {
        ERROR("srtp keys length less then expected: own - %d, other - %d", key_own_len, key_other_len);
        return;
    }
    rtp_mode = SRTP_EXTERNAL_KEYS;
    memcpy(c_keys[0], key_own, SRTP_KEY_SIZE);
    memcpy(c_keys[1], key_other, SRTP_KEY_SIZE);
}

void AmSrtpConnection::tls_emit_data(const uint8_t data[], size_t size)
{
}

void AmSrtpConnection::tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size)
{
}

void AmSrtpConnection::tls_alert(Botan::TLS::Alert alert)
{
}

bool AmSrtpConnection::tls_session_established(const Botan::TLS::Session& session)
{
}

void AmSrtpConnection::tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>& cert_chain,
                            const std::vector<std::shared_ptr<const Botan::OCSP::Response>>& ocsp_responses,
                            const std::vector<Botan::Certificate_Store*>& trusted_roots,
                            Botan::Usage_Type usage,
                            const std::string& hostname,
                            const Botan::TLS::Policy& policy)
{
}

#include "AmSrtpConnection.h"
#include "AmRtpStream.h"

#include <botan/tls_client.h>
#include <botan/tls_server.h>
#include <botan/pkcs8.h>
#include <botan/dl_group.h>

dtls_conf::dtls_conf()
: s_client(0), s_server(0)
, is_optional(false)
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

std::vector<uint16_t> dtls_conf::srtp_profiles() const
{
    std::vector<uint16_t> profiles;
    profiles.push_back(srtp_profile_aes128_cm_sha1_80);
    profiles.push_back(srtp_profile_aes128_cm_sha1_32);
    profiles.push_back(srtp_profile_null_sha1_80);
    profiles.push_back(srtp_profile_null_sha1_32);
    return profiles;
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
    srtp_init();
    memset(&srtp_policy, 0, sizeof(srtp_policy_t));
    mki_id = 1;
    mkey[0].key = c_key;
    mkey[0].mki_id = &mki_id;
    mkey[0].mki_size = MKI_SIZE;
    srtp_policy.keys  = (srtp_master_key_t**)&mkey;
    srtp_policy.num_master_keys  = 1;
}

AmSrtpConnection::~AmSrtpConnection()
{
    if(dtls_channel) {
        delete dtls_channel;
    }
}

void AmSrtpConnection::create_dtls()
{
    try {
        if(rtp_mode == DTLS_SRTP_CLIENT) {
            dtls_channel = new Botan::TLS::Client(*this, *session_manager_dtls::instance(), *dtls_settings, *dtls_settings,*rand_generator_dtls::instance(),
                                                Botan::TLS::Server_Information(rtp_stream->getRHost().c_str(), rtp_stream->getRPort()),
                                                Botan::TLS::Protocol_Version::DTLS_V12);
        } else if(rtp_mode == DTLS_SRTP_SERVER){
            dtls_channel = new Botan::TLS::Server(*this, *session_manager_dtls::instance(), *dtls_settings, *dtls_settings,*rand_generator_dtls::instance(), false);
        } else {
            ERROR("incorrect mode before creation dtls:%d", rtp_mode);
        }
    } catch(Botan::Exception& exc) {
      ERROR("unforseen error in dtls:%s",
                      exc.what());
      dtls_channel = 0;
    }
}

void AmSrtpConnection::use_dtls(dtls_client_settings* settings)
{
    rtp_mode = DTLS_SRTP_CLIENT;
    dtls_settings.reset(new dtls_conf(settings));
    create_dtls();
}

void AmSrtpConnection::use_dtls(dtls_server_settings* settings)
{
    rtp_mode = DTLS_SRTP_SERVER;
    dtls_settings.reset(new dtls_conf(settings));
    create_dtls();
}

void AmSrtpConnection::use_key(srtp_profile_t profile, unsigned char* key, unsigned int key_len)
{
    if(key_len < SRTP_KEY_SIZE) {
        ERROR("srtp keys length less then expected: len - %d", key_len);
        return;
    }
    rtp_mode = SRTP_EXTERNAL_KEY;
    memcpy(c_key, key, SRTP_KEY_SIZE);
    srtp_crypto_policy_set_from_profile_for_rtp(&srtp_policy.rtp, profile);
    srtp_create(&srtp_session, &srtp_policy);
}

bool AmSrtpConnection::on_data_recv(uint8_t* data, size_t size)
{
    if(!dtls_channel) {
        return false;
    }
    if(rtp_mode == DTLS_SRTP_SERVER || rtp_mode == DTLS_SRTP_CLIENT) {
        dtls_channel->received_data(data, size);
    } else if(rtp_mode == SRTP_EXTERNAL_KEY){

    }
    return false;
}

bool AmSrtpConnection::on_data_send(uint8_t* data, size_t size)
{
    if(!dtls_channel) {
        return false;
    }

    if(rtp_mode == SRTP_EXTERNAL_KEY){

    }
    return false;
}

void AmSrtpConnection::tls_emit_data(const uint8_t data[], size_t size)
{
    assert(rtp_stream);

    rtp_stream->send((unsigned char*)data, size);
}

void AmSrtpConnection::tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size)
{
}

void AmSrtpConnection::tls_alert(Botan::TLS::Alert alert)
{
}

bool AmSrtpConnection::tls_session_established(const Botan::TLS::Session& session)
{
    DBG("************ on_dtls_connect() ***********");
    DBG("new DTLS connection from %s:%u",
        rtp_stream->getRHost().c_str(),
        rtp_stream->getRPort());

    Botan::SymmetricKey key = dtls_channel->key_material_export(rtp_stream->getRHost().c_str(), "", SRTP_KEY_SIZE);
    use_key((srtp_profile_t)session.dtls_srtp_profile(), (unsigned char*)key.begin(), key.end() - key.begin());
    return true;
}

void AmSrtpConnection::tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>& cert_chain,
                            const std::vector<std::shared_ptr<const Botan::OCSP::Response>>& ocsp_responses,
                            const std::vector<Botan::Certificate_Store*>& trusted_roots,
                            Botan::Usage_Type usage,
                            const std::string& hostname,
                            const Botan::TLS::Policy& policy)
{
    if((dtls_settings->s_client && !dtls_settings->s_client->verify_certificate_chain) ||
        (dtls_settings->s_server && !dtls_settings->s_server->verify_client_certificate)) {
        return;
    }

    if(dtls_settings->s_client && !dtls_settings->s_client->verify_certificate_cn)
        Botan::TLS::Callbacks::tls_verify_cert_chain(cert_chain, ocsp_responses, trusted_roots, usage, "", policy);
    else
        Botan::TLS::Callbacks::tls_verify_cert_chain(cert_chain, ocsp_responses, trusted_roots, usage, hostname, policy);
}

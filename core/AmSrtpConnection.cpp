#include "AmSrtpConnection.h"
#include "AmRtpStream.h"

#include <botan/tls_client.h>
#include <botan/tls_server.h>
#include <botan/pkcs8.h>
#include <botan/dl_group.h>
#include <botan/base64.h>
#include <botan/uuid.h>
#include "rtp/rtp.h"

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
    if(conf.s_server && !conf.s_server->certificate_key.empty()) {
        key = std::unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(conf.s_server->certificate_key, *rand_generator_dtls::instance()));
    } else if(conf.s_client && !conf.s_client->certificate_key.empty()) {
        key = std::unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(conf.s_client->certificate_key, *rand_generator_dtls::instance()));
    }
}

void dtls_conf::operator=(const dtls_conf& conf)
{
    s_client = conf.s_client;
    s_server = conf.s_server;
    certificate = conf.certificate;
    is_optional = conf.is_optional;
    if(conf.s_server && !conf.s_server->certificate_key.empty()) {
        key = std::unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(conf.s_server->certificate_key, *rand_generator_dtls::instance()));
    } else if(conf.s_client && !conf.s_client->certificate_key.empty()) {
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
    dtls_settings* settings = 0;
    if(s_client) {
        settings = s_client;
    } else if(s_server) {
        settings = s_server;
    }

    if(!settings) {
        ERROR("incorrect pointer");
        return std::vector<uint16_t>();
    }

    return settings->srtp_profiles;
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

AmSrtpConnection::AmSrtpConnection(AmRtpStream* stream, bool srtcp)
: rtp_mode(RTP_DEFAULT), rtp_stream(stream), dtls_settings(0)
, dtls_channel(0), srtp_s_session(0), srtp_r_session(0), srtp_profile(srtp_profile_reserved), b_srtcp(srtcp)
{
    memset(b_init, 0, sizeof(b_init));
}

AmSrtpConnection::~AmSrtpConnection()
{
    if(dtls_channel) {
        delete dtls_channel;
    }

    if(srtp_s_session) {
        srtp_dealloc(srtp_s_session);
        srtp_s_session = 0;
    }
    if(srtp_r_session) {
        srtp_dealloc(srtp_r_session);
        srtp_r_session = 0;
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
            dtls_channel = new Botan::TLS::Server(*this, *session_manager_dtls::instance(), *dtls_settings, *dtls_settings,*rand_generator_dtls::instance(), true);
        } else {
            ERROR("incorrect mode before creation dtls:%d", rtp_mode);
        }
    } catch(Botan::Exception& exc) {
        ERROR("unforseen error in dtls:%s",
                        exc.what());
        dtls_channel = 0;
    }
}

bool AmSrtpConnection::isRtpPacket(uint8_t* data, unsigned int size)
{
    rtp_hdr_t* rtp = (rtp_hdr_t*)data;
    if(rtp->version == RTP_VERSION) {
        return true;
    }
}

void AmSrtpConnection::use_dtls(dtls_client_settings* settings)
{
    if(rtp_mode == DTLS_SRTP_SERVER) {
        return;
    }
    rtp_mode = DTLS_SRTP_CLIENT;
    try {
        dtls_settings.reset(new dtls_conf(settings));
    } catch(Botan::Exception& exc) {
        ERROR("unforseen error in dtls:%s",
                        exc.what());
        return;
    }

    create_dtls();
}

void AmSrtpConnection::use_dtls(dtls_server_settings* settings)
{
    if(rtp_mode == DTLS_SRTP_SERVER) {
        return;
    }
    rtp_mode = DTLS_SRTP_SERVER;
    try {
        dtls_settings.reset(new dtls_conf(settings));
    } catch(Botan::Exception& exc) {
        ERROR("unforseen error in dtls:%s",
                        exc.what());
        return;
    }
    create_dtls();
}

void AmSrtpConnection::use_key(srtp_profile_t profile, unsigned char* key_s, unsigned int key_s_len, unsigned char* key_r, unsigned int key_r_len)
{
    if(srtp_s_session || srtp_r_session) {
        return;
    }

    unsigned int master_key_len = srtp_profile_get_master_key_length(profile);
    master_key_len += srtp_profile_get_master_salt_length(profile);
    if(master_key_len != key_s_len || master_key_len != key_r_len) {
        CLASS_ERROR("srtp key not corrected, another size: needed %u in fact local-%u, remote-%u",
                    master_key_len, key_s_len, key_r_len);
        return;
    }

    if (srtp_create(&srtp_s_session, NULL) != srtp_err_status_ok ||
        srtp_create(&srtp_r_session, NULL) != srtp_err_status_ok) {
        CLASS_ERROR("srtp session not created");
        return;
    }


    memcpy(c_key_s, key_s, key_s_len);
    memcpy(c_key_r, key_r, key_r_len);
    srtp_profile = profile;
    rtp_mode = SRTP_EXTERNAL_KEY;
}


void AmSrtpConnection::base64_key(const std::string& key, unsigned char* key_s, unsigned int& key_s_len)
{
    Botan::secure_vector<uint8_t> data = Botan::base64_decode(key);
    if(data.size() > key_s_len) {
        ERROR("key buffer less base64 decoded key");
        return;
    }
    key_s_len = data.size();
    memcpy(key_s, data.data(), key_s_len);
}

std::string AmSrtpConnection::gen_base64_key(srtp_profile_t profile)
{
    unsigned int len = 0;
    std::vector<uint8_t> data;
    unsigned int master_key_len = srtp_profile_get_master_key_length(profile);
    master_key_len += srtp_profile_get_master_salt_length(profile);
    while(len != master_key_len) {
        const Botan::UUID random_uuid(*rand_generator_dtls::instance());
        if(master_key_len < len + random_uuid.binary_value().size()) {
            data.insert(data.end(), random_uuid.binary_value().begin(), random_uuid.binary_value().begin() + (master_key_len - len));
        } else {
            data.insert(data.end(), random_uuid.binary_value().begin(), random_uuid.binary_value().end());
        }
        len = data.size();
    }
    return Botan::base64_encode(data);
}

int AmSrtpConnection::on_data_recv(uint8_t* data, unsigned int* size, bool rtcp)
{
    if(!b_init[1] && rtp_mode == SRTP_EXTERNAL_KEY) {
        CLASS_INFO("create srtp stream for receving stream");
        srtp_policy_t policy;
        memset(&policy, 0, sizeof(policy));
        srtp_crypto_policy_set_from_profile_for_rtp(&policy.rtp, srtp_profile);
        srtp_crypto_policy_set_from_profile_for_rtcp(&policy.rtcp, srtp_profile);
        policy.key = c_key_r;
        policy.window_size = 128;
        policy.num_master_keys = 1;
        policy.ssrc.value = rtp_stream->r_ssrc;
        policy.ssrc.type = ssrc_any_inbound;
        if(srtp_add_stream(srtp_r_session, &policy) != srtp_err_status_ok) {
            CLASS_ERROR("srtp recv stream not added");
            return SRTP_PACKET_PARSE_ERROR;
        }
        b_init[1] = true;
    }

    if((rtp_mode == DTLS_SRTP_SERVER || rtp_mode == DTLS_SRTP_CLIENT) && dtls_channel) {
        if(isRtpPacket(data, *size)) return SRTP_PACKET_PARSE_RTP;
        try {
            size_t res = dtls_channel->received_data(data, *size);
            if(res > 0) {
                CLASS_DBG("need else %llu", res);
            }
        } catch(Botan::Exception& exc) {
            ERROR("unforseen error in dtls:%s",
                            exc.what());
            return SRTP_PACKET_PARSE_ERROR;
        }
        return SRTP_PACKET_PARSE_OK;
    } else if(rtp_mode == SRTP_EXTERNAL_KEY && srtp_r_session){
        srtp_err_status_t ret;
        if(!rtcp)
            ret = srtp_unprotect(srtp_r_session, data, (int*)size);
        else
            ret = srtp_unprotect_rtcp(srtp_r_session, data, (int*)size);
        return (ret == srtp_err_status_ok) ? SRTP_PACKET_PARSE_OK : SRTP_PACKET_PARSE_ERROR;
    }
    return SRTP_PACKET_PARSE_ERROR;
}

bool AmSrtpConnection::on_data_send(uint8_t* data, unsigned int* size, bool rtcp)
{

    if(!b_init[0] && rtp_mode == SRTP_EXTERNAL_KEY) {
        CLASS_INFO("create srtp stream for sending stream");
        srtp_policy_t policy;
        memset(&policy, 0, sizeof(policy));
        srtp_crypto_policy_set_from_profile_for_rtp(&policy.rtp, srtp_profile);
        srtp_crypto_policy_set_from_profile_for_rtcp(&policy.rtcp, srtp_profile);
        policy.key = c_key_s;
        policy.window_size = 128;
        policy.num_master_keys = 1;
        policy.ssrc.value = rtp_stream->l_ssrc;
        policy.ssrc.type = ssrc_any_outbound;
        if(srtp_add_stream(srtp_s_session, &policy) != srtp_err_status_ok) {
            CLASS_ERROR("srtp send stream not added");
            return false;
        }
        b_init[0] = true;
    }
    if(rtp_mode == SRTP_EXTERNAL_KEY && srtp_s_session){
        if(!rtcp) {
            uint32_t trailer_len = 0;
            srtp_get_protect_trailer_length(srtp_s_session, false, 0, &trailer_len);
            if(*size + trailer_len <= RTP_PACKET_BUF_SIZE)
                return srtp_protect(srtp_s_session, data, (int*)size) == srtp_err_status_ok;
            else
                return false;
        } else {
            return srtp_protect_rtcp(srtp_s_session, data, (int*)size) == srtp_err_status_ok;
        }
    }
    return false;
}

void AmSrtpConnection::tls_emit_data(const uint8_t data[], size_t size)
{
    assert(rtp_stream);

    rtp_stream->send((unsigned char*)data, size, b_srtcp);
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

    srtp_profile = (srtp_profile_t)session.dtls_srtp_profile();
    return true;
}

void AmSrtpConnection::tls_session_activated()
{
    unsigned int key_len = srtp_profile_get_master_key_length(srtp_profile);
    unsigned int salt_size = srtp_profile_get_master_salt_length(srtp_profile);
    unsigned int export_key_size = key_len*2 + salt_size*2;
    Botan::SymmetricKey key = dtls_channel->key_material_export("EXTRACTOR-dtls_srtp", "", export_key_size);
    std::vector<uint8_t> local_key, remote_key;
    if(dtls_settings->s_server) {
        remote_key.insert(remote_key.end(), key.begin(), key.begin() + key_len);
        local_key.insert(local_key.end(), key.begin() + key_len, key.begin() + key_len*2);
        remote_key.insert(remote_key.end(), key.begin() + key_len*2, key.begin() + key_len*2 + salt_size);
        local_key.insert(local_key.end(), key.begin() + key_len*2 + salt_size, key.end());
    } else {//TODO: need approve for client side,
        local_key.insert(local_key.end(), key.begin(), key.begin() + key_len);
        remote_key.insert(remote_key.end(), key.begin() + key_len, key.begin() + key_len*2);
        local_key.insert(local_key.end(), key.begin() + key_len*2, key.begin() + key_len*2 + salt_size);
        remote_key.insert(remote_key.end(), key.begin() + key_len*2 + salt_size, key.end());
    }
    use_key(srtp_profile, (unsigned char*)local_key.data(), local_key.size(), (unsigned char*)remote_key.data(), remote_key.size());
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

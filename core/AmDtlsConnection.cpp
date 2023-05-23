#include "AmDtlsConnection.h"
#include "AmSrtpConnection.h"
#include "AmMediaTransport.h"

#include <botan/tls_client.h>
#include <botan/tls_server.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_alert.h>
#include <botan/data_src.h>
#include <botan/pkcs8.h>
#include <botan/dl_group.h>
#include "AmLCContainers.h"
#include "AmLcConfig.h"
#include "AmRtpStream.h"

#define DTLS_TIMER_INTERVAL_MS 1000

dtls_conf::dtls_conf()
: s_client(0), s_server(0)
, is_optional(false)
{
}

dtls_conf::dtls_conf(const dtls_conf& conf)
: s_client(conf.s_client), s_server(conf.s_server)
, certificates(conf.certificates)
, key(Botan::PKCS8::copy_key(*conf.key.get()))
, is_optional(conf.is_optional) {}

dtls_conf::dtls_conf(dtls_client_settings* settings)
: s_client(settings), s_server(0)
, certificates(settings->getCertificateCopy())
, key(settings->getCertificateKeyCopy())
, is_optional(false){}

dtls_conf::dtls_conf(dtls_server_settings* settings)
: s_client(0), s_server(settings)
, certificates(settings->getCertificateCopy())
, key(settings->getCertificateKeyCopy())
, is_optional(false){}

void dtls_conf::operator=(const dtls_conf& conf)
{
    s_client = conf.s_client;
    s_server = conf.s_server;
    certificates = conf.certificates;
    is_optional = conf.is_optional;
    key.reset(Botan::PKCS8::copy_key(*conf.key.get()).release());
}

std::shared_ptr<Botan::Private_Key> dtls_conf::private_key_for(
    const Botan::X509_Certificate& cert,
    const string& type,
    const string& context)
{
    if(key) {
        return key;
    }
    return nullptr;
}

vector<Botan::Certificate_Store *> dtls_conf::trusted_certificate_authorities(const string& type, const string& context)
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

    return settings->getCertificateAuthorityCopy();
}

bool dtls_conf::allow_dtls12() const
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

void dtls_conf::set_optional_parameters(string sig_, string cipher_, string mac_)
{
    is_optional = true;
    cipher = cipher_;
    mac = mac_;
    sig = sig_;
}

vector<uint16_t> dtls_conf::srtp_profiles() const
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

vector<string> dtls_conf::allowed_key_exchange_methods() const
{
    if(s_client && is_optional) {
        return {sig };
    } else {
        return Policy::allowed_key_exchange_methods();
    }
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

vector<string> dtls_conf::allowed_signature_methods() const
{
    if(s_client && is_optional) {
        return {"IMPLICIT"};
    } else {
        return Policy::allowed_signature_methods();
    }
}

vector<Botan::X509_Certificate> dtls_conf::cert_chain(
    const vector<string>& cert_key_types,
    const std::vector<Botan::AlgorithmIdentifier>& cert_signature_schemes,
    const string& type,
    const string& context)
{
    vector<Botan::X509_Certificate> certs;
    for(auto& cert : certificates) {
        std::string algorithm = cert.subject_public_key()->algo_name();
        for(auto& key : cert_key_types) {
            if(algorithm == key) {
                DBG("added certificate with algorithm %s", algorithm.c_str());
                certs.push_back(cert);
            }
        }
    }

    if(certs.empty()) {
        for(auto& key : cert_key_types) {
            DBG("no certificates for algorithms %s", key.c_str());
        }
    }
    return certs;
}

DtlsTimer::DtlsTimer(AmDtlsConnection* connection)
: conn(connection),
  is_valid(true)
{
    inc_ref(this);
    reset();
}

DtlsTimer::~DtlsTimer()
{ }

void DtlsTimer::fire()
{
    if(!is_valid.load()) {
        dec_ref(this);
        return;
    }
    if(conn->timer_check()) {
        reset();
    } else {
        dec_ref(this);
    }
}

void DtlsTimer::invalidate()
{
    is_valid.store(false);
}

void DtlsTimer::reset()
{
    expires =
        DTLS_TIMER_INTERVAL_MS/(TIMER_RESOLUTION/DTLS_TIMER_INTERVAL_MS) + wheeltimer::instance()->wall_clock;
    wheeltimer::instance()->insert_timer(this);
}

AmDtlsConnection::AmDtlsConnection(AmMediaTransport* _transport, const string& remote_addr, int remote_port, const srtp_fingerprint_p& _fingerprint, bool client)
  : AmStreamConnection(_transport, remote_addr, remote_port, AmStreamConnection::DTLS_CONN),
    tls_callbacks_proxy(std::make_shared<BotanTLSCallbacksProxy>(*this)),
    dtls_channel(nullptr),
    dtls_settings(),
    fingerprint(_fingerprint),
    srtp_profile(srtp_profile_reserved),
    rand_gen(std::make_shared<Botan::AutoSeeded_RNG>()),
    activated(false),
    is_client(client),
    pending_handshake_timer(nullptr)
{
    initConnection();
}

AmDtlsConnection::~AmDtlsConnection()
{
    if(pending_handshake_timer) {
        pending_handshake_timer->invalidate();
        dec_ref(pending_handshake_timer);
    }

    if(dtls_channel) {
        delete dtls_channel;
    }
}

void AmDtlsConnection::initConnection()
{
    if(dtls_channel) {
        if(pending_handshake_timer) {
            pending_handshake_timer->invalidate();
            dec_ref(pending_handshake_timer);
            pending_handshake_timer = nullptr;
        }
        delete dtls_channel;
    }

    RTP_info* rtpinfo = RTP_info::toMEDIA_RTP(AmConfig.media_ifs[transport->getLocalIf()].proto_info[transport->getLocalProtoId()]);
    try {
        if(is_client) {
            dtls_settings = std::make_shared<dtls_conf>(&rtpinfo->client_settings);
            dtls_channel = new Botan::TLS::Client(
                tls_callbacks_proxy,
                session_manager_dtls::instance()->ssm,
                dtls_settings,
                dtls_settings,
                rand_gen,
                Botan::TLS::Server_Information(
                    r_host.c_str(), r_port),
                    Botan::TLS::Protocol_Version::DTLS_V12);
        } else {
            dtls_settings = std::make_shared<dtls_conf>(&rtpinfo->server_settings);
            dtls_channel = new Botan::TLS::Server(
                tls_callbacks_proxy,
                session_manager_dtls::instance()->ssm,
                dtls_settings,
                dtls_settings,
                rand_gen,
                true);
        }

        pending_handshake_timer = new DtlsTimer(this);
        inc_ref(pending_handshake_timer);
    } catch(Botan::Exception& exc) {
        dtls_channel = 0;
        throw string("unforseen error in dtls:%s",
                        exc.what());
    }
}

srtp_fingerprint_p AmDtlsConnection::gen_fingerprint(class dtls_settings* settings)
{
    static std::string hash("SHA-256");
    return srtp_fingerprint_p(hash, settings->getCertificateFingerprint(hash));
}

void AmDtlsConnection::handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time)
{
    try {
        size_t res = dtls_channel->received_data(data, size);
        if(res > 0) {
            CLASS_DBG("need else %zu", res);
        }
    } catch(Botan::Exception& exc) {
        string error("unforseen error in dtls:");
        transport->getRtpStream()->onErrorRtpTransport(DTLS_ERROR, error + exc.what(), transport);
    }
}

ssize_t AmDtlsConnection::send(AmRtpPacket* packet)
{
    if(activated) {
        dtls_channel->send((const uint8_t*)packet->getBuffer(), packet->getBufferSize());
        return packet->getBufferSize();
    }
    return 0;
}

bool AmDtlsConnection::timer_check()
{
    if(!activated) {
        dtls_channel->timeout_check();
        return true;
    }
    return false;
}

void AmDtlsConnection::tls_alert(Botan::TLS::Alert alert)
{
}

void AmDtlsConnection::tls_emit_data(std::span<const uint8_t> data)
{
    assert(transport);
    transport->send(
        &r_addr,
        (unsigned char*)data.data(), data.size(),
        AmStreamConnection::DTLS_CONN);
}

void AmDtlsConnection::tls_record_received(uint64_t seq_no, std::span<const uint8_t> data)
{
    sockaddr_storage laddr;
    transport->getLocalAddr(&laddr);
    AmRtpPacket* p = transport->getRtpStream()->createRtpPacket();
    if(!p) return;
    p->recv_time = last_recv_time;
    p->relayed = false;
    p->setAddr(&r_addr);
    p->setLocalAddr(&laddr);
    p->setBuffer((unsigned char*)data.data(), data.size());
    transport->onRawPacket(p, this);
}

void AmDtlsConnection::tls_session_activated()
{
    unsigned int key_len = srtp::profile_get_master_key_length(srtp_profile);
    unsigned int salt_size = srtp::profile_get_master_salt_length(srtp_profile);
    unsigned int export_key_size = key_len*2 + salt_size*2;
    Botan::SymmetricKey key = dtls_channel->key_material_export("EXTRACTOR-dtls_srtp", "", export_key_size);
    vector<uint8_t> local_key, remote_key;
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

    transport->dtlsSessionActivated(srtp_profile, local_key, remote_key);
    activated = true;
}

void AmDtlsConnection::tls_session_established(const Botan::TLS::Session_Summary& session)
{
    DBG("************ on_dtls_connect() ***********");
    DBG("new DTLS connection from %s:%u", r_host.c_str(),r_port);

    srtp_profile = (srtp_profile_t)session.dtls_srtp_profile();
}

void AmDtlsConnection::tls_verify_cert_chain(
    const std::vector<Botan::X509_Certificate>& cert_chain,
    const std::vector<std::optional<Botan::OCSP::Response>>& ocsp_responses,
    const std::vector<Botan::Certificate_Store*>& trusted_roots,
    Botan::Usage_Type usage,
    std::string_view hostname,
    const Botan::TLS::Policy& policy)
{
    if((dtls_settings->s_client && !dtls_settings->s_client->verify_certificate_chain &&
        !dtls_settings->s_client->verify_certificate_cn) ||
        (dtls_settings->s_server && !dtls_settings->s_server->verify_client_certificate)) {
        return;
    }

    if(dtls_settings->s_client && dtls_settings->s_client->verify_certificate_cn) {
        if(!dtls_settings->s_client->verify_certificate_chain) {
            if(!cert_chain[0].matches_dns_name(hostname))
                throw Botan::TLS::TLS_Exception(Botan::TLS::AlertType::BadCertificateStatusResponse, "Verify common name certificate failed");
        } else
            Botan::TLS::Callbacks::tls_verify_cert_chain(cert_chain, ocsp_responses, trusted_roots, usage, "", policy);
    } else
        Botan::TLS::Callbacks::tls_verify_cert_chain(cert_chain, ocsp_responses, trusted_roots, usage, hostname, policy);

    std::transform(fingerprint.hash.begin(), fingerprint.hash.end(), fingerprint.hash.begin(), static_cast<int(*)(int)>(std::toupper));
    if(fingerprint.is_use && cert_chain[0].fingerprint(fingerprint.hash) != fingerprint.value)
        throw Botan::TLS::TLS_Exception(Botan::TLS::AlertType::BadCertificateHashValue, "fingerprint is not equal");
}

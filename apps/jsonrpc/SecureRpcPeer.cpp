#include "SecureRpcPeer.h"
#include "JsonRPC.h"

#include <botan/tls_client.h>
#include <botan/tls_server.h>
#include <botan/pkcs8.h>
#include <botan/dl_group.h>
#include <botan/data_src.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_alert.h>
#include <botan/tls_magic.h>
#include <botan/internal/tls_channel_impl.h>

tls_rpc_conf::tls_rpc_conf(tls_settings* settings)
: certificates(settings->getCertificateCopy())
, key(settings->getCertificateKeyCopy())
, policy_override(false)
{
    s_client = dynamic_cast<tls_client_settings*>(settings);
    s_server = dynamic_cast<tls_server_settings*>(settings);
}

tls_rpc_conf::tls_rpc_conf(const tls_rpc_conf& conf)
: s_client(conf.s_client), s_server(conf.s_server)
, certificates(conf.certificates)
, key(Botan::PKCS8::copy_key(*conf.key.get()))
, policy_override(conf.policy_override)
, cipher(conf.cipher)
, mac(conf.mac)
, sig(conf.sig) {}


void tls_rpc_conf::operator=(const tls_rpc_conf& conf)
{
    s_client = conf.s_client;
    s_server = conf.s_server;
    certificates = conf.certificates;
    key.reset(Botan::PKCS8::copy_key(*conf.key.get()).release());
    policy_override = conf.policy_override;
    cipher = conf.cipher;
    mac = conf.mac;
    sig = conf.sig;
}

vector<string> tls_rpc_conf::allowed_key_exchange_methods() const
{
    if(s_client && !sig.empty()) {
        return {sig };
    } else {
        return {
            "SRP_SHA",
            /*"ECDHE_PSK",
            "DHE_PSK",
            "PSK",*/
            "CECPQ1",
            "ECDH",
            "DH",
            "RSA"
        };
        //return Policy::allowed_key_exchange_methods();
    }
}

vector<string> tls_rpc_conf::allowed_signature_methods() const
{
    return {
       "ECDSA",
       "RSA",
       "DSA",
       "IMPLICIT",
       //"ANONYMOUS" (anon)
    };
    //return Policy::allowed_signature_methods();
}

vector<string> tls_rpc_conf::allowed_ciphers() const
{
    if(s_server) {
        return s_server->cipher_list;
    } else if(s_client && !cipher.empty()) {
        return { cipher };
    } else if(s_client) {
        return {
           "AES-256/OCB(12)",
           "AES-128/OCB(12)",
           "ChaCha20Poly1305",
           "AES-256/GCM",
           "AES-128/GCM",
           "AES-256/CCM",
           "AES-128/CCM",
           "AES-256/CCM(8)",
           "AES-128/CCM(8)",
           "Camellia-256/GCM",
           "Camellia-128/GCM",
           "ARIA-256/GCM",
           "ARIA-128/GCM",
           "AES-256",
           "AES-128",
           "Camellia-256",
           "Camellia-128",
           "SEED",
           "3DES"
        };
        //return Policy::allowed_ciphers();
    }
    ERROR("allowed_ciphers: called in unexpected context");
    return vector<string>();
}

vector<string> tls_rpc_conf::allowed_macs() const
{
    if(s_server) {
        return s_server->macs_list;
    } else if(s_client && !mac.empty()) {
        return {mac };
    } else if(s_client) {
        return Policy::allowed_macs();
    }
    ERROR("allowed_ciphers: called in unexpected context");
    return vector<string>();
}

size_t tls_rpc_conf::minimum_rsa_bits() const
{
    return 1024;
}

bool tls_rpc_conf::allow_tls12()  const
{
    tls_settings* settings = 0;
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
        if(proto == tls_client_settings::TLSv1_2) {
            return true;
        }
    }

    return false;
}

vector<Botan::Certificate_Store*> tls_rpc_conf::trusted_certificate_authorities(const string& type, const string& context)
{
    tls_settings* settings = 0;
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

vector<Botan::X509_Certificate> tls_rpc_conf::cert_chain(
    const std::vector<std::string>& cert_key_types,
    const std::vector<Botan::AlgorithmIdentifier>& cert_signature_schemes,
    const std::string& type,
    const std::string& context)
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
            DBG("no certificates for algorithm %s", key.c_str());
        }
    }
    return certs;
}

std::shared_ptr<Botan::Private_Key> tls_rpc_conf::private_key_for(const Botan::X509_Certificate& cert, const string& type, const string& context)
{
    if(key) {
        return key;
    }
    return nullptr;
}

bool tls_rpc_conf::require_client_certificate_authentication() const
{
    if(s_server) return s_server->require_client_certificate;
    return false;
}

void tls_rpc_conf::set_policy_overrides(std::string sig_, std::string cipher_, std::string mac_)
{
    policy_override = true;
    cipher = cipher_;
    mac = mac_;
    sig = sig_;
    DBG("set optional parameters in tls session: cipher:'%s', mac:'%s', sig:'%s'",
        cipher.c_str(), mac.c_str(), sig.c_str());
}

void SecureRpcPeer::initTls(bool server)
{
    try {
        if(server) {
            settings = std::make_shared<tls_rpc_conf>(&JsonRPCServerModule::instance()->server_settings);
            tls_channel = new Botan::TLS::Server(
                tls_callbacks,
                session_manager_tls::instance()->ssm,
                settings,
                settings,
                rand_gen,
                false);
        } else {
            settings =  std::make_shared<tls_rpc_conf>(&JsonRPCServerModule::instance()->client_settings);
            settings->set_policy_overrides("RSA","AES-128","SHA-1");
            tls_channel = new Botan::TLS::Client(
                tls_callbacks,
                session_manager_tls::instance()->ssm,
                settings,
                settings,
                rand_gen,
                Botan::TLS::Server_Information(JsonRPCServerModule::instance()->host.c_str(), JsonRPCServerModule::instance()->port),
                Botan::TLS::Protocol_Version::TLS_V12);
        }
    } catch(Botan::Exception& ex) {
        ERROR("Botan tls error: %s", ex.what());
        close();
    }
}


int SecureRpcPeer::ws_recv_data(uint8_t *data, size_t len) {
    if(conn_type == PEER_WSS) {
        int ret_size = len > tls_resv_buffer.size() ? tls_resv_buffer.size() : len;
        memcpy(data, tls_resv_buffer.data(), ret_size);
        tls_resv_buffer.erase(tls_resv_buffer.begin(), tls_resv_buffer.begin() + ret_size);
        return ret_size;
    } else return WsRpcPeer::ws_recv_data(data, len);
};

int SecureRpcPeer::ws_send_data(const uint8_t* data, size_t len) {
    if(conn_type == PEER_WSS) {
        try{
            tls_channel->send(data, len);
        } catch(Botan::Exception& ex) {
            ERROR("Botan tls error: %s", ex.what());
            return 0;
        }
        return len;
    } else return WsRpcPeer::ws_send_data(data, len);
}

void SecureRpcPeer::tls_emit_data(std::span<const uint8_t> data)
{
    JsonrpcNetstringsConnection::send_data((char*)data.data(), data.size());
}

void SecureRpcPeer::tls_record_received(uint64_t seq_no, std::span<const uint8_t> data)
{
    int old_size = tls_resv_buffer.size();
    tls_resv_buffer.resize(old_size + data.size());
    memcpy(tls_resv_buffer.data() + old_size, data.data(), data.size());
}

void SecureRpcPeer::tls_alert(Botan::TLS::Alert alert)
{}

void SecureRpcPeer::tls_session_established(const Botan::TLS::Session_Summary& session)
{
    DBG("************ on_tls_connect() ***********");
    tls_connected = true;
}

void SecureRpcPeer::tls_verify_cert_chain(
    const std::vector<Botan::X509_Certificate>& cert_chain,
    const std::vector<std::optional<Botan::OCSP::Response>>& ocsp_responses,
    const std::vector<Botan::Certificate_Store*>& trusted_roots,
    Botan::Usage_Type usage,
    std::string_view hostname,
    const Botan::TLS::Policy& policy)
{
    if((settings->s_client && !settings->s_client->verify_certificate_chain && !settings->s_client->verify_certificate_cn) ||
        (settings->s_server && !settings->s_server->verify_client_certificate)) {
        return;
    }

    if(settings->s_client && settings->s_client->verify_certificate_cn) {
        if(settings->s_client->verify_certificate_chain) {
            if(!cert_chain[0].matches_dns_name(hostname))
                throw Botan::TLS::TLS_Exception(Botan::TLS::AlertType::BadCertificateStatusResponse, "Verify common name certificate failed");
        } else
            Botan::TLS::Callbacks::tls_verify_cert_chain(cert_chain, ocsp_responses, trusted_roots, usage, "", policy);
    } else
        Botan::TLS::Callbacks::tls_verify_cert_chain(cert_chain, ocsp_responses, trusted_roots, usage, hostname, policy);
}

SecureRpcPeer::SecureRpcPeer(const string& id)
  : WsRpcPeer(id),
    tls_callbacks(std::make_shared<BotanTLSCallbacksProxy>(*this)),
    rand_gen(std::make_shared<Botan::System_RNG>()),
    is_tls(false),
    tls_connected(false),
    tls_channel(nullptr)
{}

SecureRpcPeer::~SecureRpcPeer()
{
    if(tls_channel) delete tls_channel;
}

int SecureRpcPeer::connect(const string& host, int port, string& res_str)
{
    if(conn_type == PEER_TCP) return JsonrpcNetstringsConnection::connect(host, port, res_str);
    else if(conn_type == PEER_WS) return WsRpcPeer::connect(host, port, res_str);
    int ret = JsonrpcNetstringsConnection::connect(host, port, res_str);
    is_tls = true;
    initTls(false);
    if(conn_type == PEER_WSS) init_wslay(false);
    return ret;
}

int SecureRpcPeer::netstringsRead() {
    if(conn_type == PEER_TCP)
        return JsonrpcNetstringsConnection::netstringsRead();
    else if(conn_type == PEER_WS)
        return WsRpcPeer::netstringsRead();

    if(!tls_connected) {
        int r = read_data(msgbuf, 1);
        if (!r) return CONTINUE;
        if (r<0)return REMOVE;
        if (r != 1) {
            INFO("socket error on connection [%p/%d]: %s",
                this, fd, strerror(errno));
            return REMOVE;
        }

        rcvd_size += 1;

        if(conn_type == PEER_WS || conn_type == PEER_TCP)
            return CONTINUE;

        r = read_data(msgbuf + rcvd_size, MAX_RPC_MSG_SIZE - rcvd_size);
        if (!r) return CONTINUE;
        if (r<0)return REMOVE;
        rcvd_size += r;
        try {
            tls_channel->received_data((uint8_t*)msgbuf, rcvd_size);
        } catch(Botan::Exception& ex) {
            ERROR("Botan tls error: %s", ex.what());
            return REMOVE;
        }
        rcvd_size = 0;
        if(tls_connected) {
            if(conn_type == PEER_WSS) {
                WsRpcPeer::addMessage(tls_send_buffer.data(), tls_send_buffer.size());
                send_request();
            } else if(conn_type == PEER_TLS) {
                JsonrpcNetstringsConnection::addMessage(tls_send_buffer.data(), tls_send_buffer.size());
                if(JsonrpcNetstringsConnection::netstringsBlockingWrite() == REMOVE) return REMOVE;
            }
        }
        return CONTINUE;
    }

    return WsRpcPeer::netstringsRead();
}

int SecureRpcPeer::read_data(char* data, int size) {
    if(conn_type == PEER_UNKNOWN && !tls_connected && !is_tls) {
        if(size != 1) {
            ERROR("incorrect reading size of peer in initial state");
            return -1;
        }
        int r = JsonrpcNetstringsConnection::read_data(data, 1);
        if(r<0) return r;
        if(r != 1) return -1;

        // tls data
        if(*data == static_cast<char>(Botan::TLS::Record_Type::Handshake)) {
            is_tls = true;
            initTls(true);
        } else if(*data == 'G'){
            conn_type = PEER_WS;
            init_wslay(true);
        // netstrings 
        } else if(*data >= '0' && *data <= '9') {
            conn_type = PEER_TCP;
        } else {
            INFO("Unsupported protocol. Must be netstring, websocket, secure websocket or secure netstring.");
            return -1;
        }
        return 1;
    } else if(conn_type == PEER_WS) {
        return WsRpcPeer::read_data(data, size);
    } else if(conn_type == PEER_TCP ||
             (conn_type == PEER_UNKNOWN && is_tls && !tls_connected) ||
             (conn_type != PEER_UNKNOWN && !tls_connected)) {
        return JsonrpcNetstringsConnection::read_data(data, size);
    }

    if(tls_resv_buffer.empty()) {
        int r = JsonrpcNetstringsConnection::read_data(msgbuf + rcvd_size, MAX_RPC_MSG_SIZE - rcvd_size);
        if(r <= 0) return r;
        try {
            tls_channel->received_data((uint8_t*)msgbuf + rcvd_size, r);
        } catch(Botan::Exception& ex) {
            ERROR("Botan tls error: %s", ex.what());
            return -1;
        }
    }

    if(conn_type == PEER_UNKNOWN && tls_connected) {
        if(tls_resv_buffer.empty()) return -1;
        char *data = tls_resv_buffer.data();
        if(*data == 'G'){
            conn_type = PEER_WSS;
            init_wslay(true);
        // netstrings 
        } else if(*data >= '0' && *data <= '9') {
            conn_type = PEER_TLS;
        } else {
            INFO("Unsupported protocol. Must be netstring, websocket, secure websocket or secure netstring.");
            return -1;
        }
    }

    if(conn_type == PEER_WSS && ws_connected) {
        return WsRpcPeer::read_data(data, size);
    } else {
        int ret_size = size > static_cast<typeof size>(tls_resv_buffer.size()) ?
            tls_resv_buffer.size() : size;

        memcpy(data, tls_resv_buffer.data(), ret_size);
        tls_resv_buffer.erase(tls_resv_buffer.begin(), tls_resv_buffer.begin() + ret_size);
        return ret_size;
    }
}

int SecureRpcPeer::netstringsBlockingWrite() {
    if(conn_type == PEER_TCP)
        return JsonrpcNetstringsConnection::netstringsBlockingWrite();
    if(conn_type == PEER_WS || tls_connected)
        return WsRpcPeer::netstringsBlockingWrite();

    if(!send_data(msgbuf, msg_size)) return REMOVE;
    rcvd_size = 0;
    msg_size = 0;
    return CONTINUE;
}

int SecureRpcPeer::send_data(char* data, int size) {
    if(conn_type == PEER_TCP || (!tls_connected && is_tls))
        return JsonrpcNetstringsConnection::send_data(data, size);
    else if(conn_type == PEER_WS)
        return WsRpcPeer::send_data(data, size);

    if(conn_type == PEER_WSS && ws_connected) {
        return WsRpcPeer::send_data(data, size);
    } else {
        try {
            tls_channel->send((const uint8_t*)data, size);
        } catch(Botan::Exception& ex) {
            ERROR("Botan tls error: %s", ex.what());
            return 0;
        }
    }
    return size;
}

void SecureRpcPeer::addMessage(const char* data, size_t len) {
    if(conn_type == PEER_TCP || tls_connected) JsonrpcNetstringsConnection::addMessage(data, len);
    else if(conn_type == PEER_WS) WsRpcPeer::addMessage(data, len);
    else {
        int old_size = tls_send_buffer.size();
        tls_send_buffer.resize(old_size + len);
        memcpy(tls_send_buffer.data() + old_size, data, len);
    }
}

void SecureRpcPeer::clearMessage() {
    tls_send_buffer.clear();
    WsRpcPeer::clearMessage();
}

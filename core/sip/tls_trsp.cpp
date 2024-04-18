#include "tls_trsp.h"
#include "trans_layer.h"
#include "socket_ssl.h"
#include "sip_parser.h"

#include "AmUtils.h"

#include <netdb.h>
#include <event2/event.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <AmLcConfig.h>

#include <botan/tls_client.h>
#include <botan/tls_server.h>
#include <botan/pkcs8.h>
#include <botan/dl_group.h>
#include <botan/data_src.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_alert.h>

tls_conf::tls_conf(tls_settings* settings)
  : certificates(settings->getCertificateCopy()),
    key(settings->getCertificateKeyCopy()),
    policy_override(false)
{
    s_client = dynamic_cast<tls_client_settings*>(settings);
    s_server = dynamic_cast<tls_server_settings*>(settings);
}

tls_conf::tls_conf(const tls_conf& conf)
  : s_client(conf.s_client), s_server(conf.s_server),
    certificates(conf.certificates),
    key(Botan::PKCS8::copy_key(*conf.key.get())),
    policy_override(conf.policy_override),
    cipher(conf.cipher),
    mac(conf.mac),
    sig(conf.sig)
{}

void tls_conf::operator=(const tls_conf& conf)
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

vector<string> tls_conf::allowed_key_exchange_methods() const
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

vector<string> tls_conf::allowed_signature_methods() const
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

vector<string> tls_conf::allowed_ciphers() const
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

vector<string> tls_conf::allowed_macs() const
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

size_t tls_conf::minimum_rsa_bits() const
{
    return 1024;
}

bool tls_conf::allow_tls12()  const
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

bool tls_conf::allow_tls13()  const
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
        if(proto == tls_client_settings::TLSv1_3) {
            return true;
        }
    }

    return false;
}

vector<Botan::Certificate_Store*> tls_conf::trusted_certificate_authorities(
    [[maybe_unused]] const string& type, [[maybe_unused]] const string& context)
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

vector<Botan::X509_Certificate> tls_conf::cert_chain(
    const vector<string>& cert_key_types,
    [[maybe_unused]] const std::vector<Botan::AlgorithmIdentifier>& cert_signature_schemes,
    [[maybe_unused]] const string& type,
    [[maybe_unused]] const string& context)
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

std::shared_ptr<Botan::Private_Key> tls_conf::private_key_for(
    [[maybe_unused]] const Botan::X509_Certificate& cert,
    [[maybe_unused]] const string& type,
    [[maybe_unused]] const string& context)
{
    if(key) {
        return key;
    }
    return nullptr;
}

bool tls_conf::require_client_certificate_authentication() const
{
    if(s_server) return s_server->require_client_certificate;
    return false;
}

void tls_conf::set_policy_overrides(std::string sig_, std::string cipher_, std::string mac_)
{
    policy_override = true;
    cipher = cipher_;
    mac = mac_;
    sig = sig_;
    DBG("set optional parameters in tls session: cipher:'%s', mac:'%s', sig:'%s'",
        cipher.c_str(), mac.c_str(), sig.c_str());
}

tls_input::tls_input()
: orig_input_len(0)
{
}

int tls_input::on_input(tcp_base_trsp* trsp)
{
    try {
        tls_trsp_socket* tls_socket = dynamic_cast<tls_trsp_socket*>(trsp);
        int ret = tls_socket->tls_channel->received_data(orig_input_buf, orig_input_len);
        reset_input();
        return ret;
    } catch(Botan::Exception& ex) {
        ERROR("Botan tls error: %s. peer %s:%d",
            ex.what(),
            trsp->get_peer_ip().data(), trsp->get_peer_port());
        return -1;
    }
}

int tls_input::on_tls_record(tcp_base_trsp* trsp, const uint8_t data[], size_t size)
{
    if(size < (size_t)trsp_base_input::get_input_free_space()) {
        memcpy(trsp_base_input::get_input(), data, size);
        trsp_base_input::add_input_len(size);
        return parse_input(trsp);
    } else {
        ERROR("message is too big. drop connection. peer %s:%d",
              trsp->get_peer_ip().data(), trsp->get_peer_port());
        throw Botan::Exception("message too big!");
    }
}

static tls_settings* getTlsSetting(int sd, int if_, int proto) {
    if(sd == -1)
        return &SIP_TLS_info::toSIP_TLS(AmConfig.sip_ifs[if_].proto_info[proto])->client_settings;
    else
        return &SIP_TLS_info::toSIP_TLS(AmConfig.sip_ifs[if_].proto_info[proto])->server_settings;
}

tls_trsp_socket::tls_trsp_socket(
    trsp_server_socket* server_sock,
    trsp_worker* server_worker,
    int sd, const sockaddr_storage* sa,
    trsp_socket::socket_transport transport,
    event_base* evbase, trsp_input* input)
  : tcp_base_trsp(server_sock, server_worker, sd, sa, transport, evbase, input),
    tls_connected(false),
    settings(std::make_shared<tls_conf>(getTlsSetting(
        sd, server_sock->get_if(), server_sock->get_proto_idx())))
{
    init(sa);
}

tls_trsp_socket::tls_trsp_socket(
    trsp_server_socket* server_sock,
    trsp_worker* server_worker,
    int sd, const sockaddr_storage* sa,
    trsp_socket::socket_transport transport, struct event_base* evbase)
  : tcp_base_trsp(server_sock, server_worker, sd, sa, transport, evbase, new tls_input),
    tls_callbacks(std::make_shared<BotanTLSCallbacksProxy>(*this)),
    tls_connected(false),
    rand_gen(std::make_shared<Botan::System_RNG>()),
    settings(std::make_shared<tls_conf>(getTlsSetting(
        sd, server_sock->get_if(), server_sock->get_proto_idx())))
{
    init(sa);
}

tls_trsp_socket::~tls_trsp_socket()
{
    if(tls_channel) {
        delete tls_channel;
    }
}

void tls_trsp_socket::init(const sockaddr_storage* sa)
{
    if(sd == -1) {
        sockaddr_ssl* sa_ssl = (sockaddr_ssl*)sa;
        if(sa_ssl->ssl_marker) {
            settings->set_policy_overrides(
                toString(sa_ssl->sig),
                toString(sa_ssl->cipher),
                toString(sa_ssl->mac));
        }

        tls_channel = new Botan::TLS::Client(
            tls_callbacks,
            session_manager_tls::instance()->ssm,
            settings,
            settings,
            rand_gen,
            Botan::TLS::Server_Information(
                get_peer_ip().c_str(), get_peer_port()),
                Botan::TLS::Protocol_Version::TLS_V12);
    } else {
        tls_channel = new Botan::TLS::Server(
            tls_callbacks,
            session_manager_tls::instance()->ssm,
            settings,
            settings,rand_gen,
            false);
    }
}

void tls_trsp_socket::generate_transport_errors()
{
    /* avoid deadlock between session processor and tcp worker.
       it is safe to unlock here because 'closed' flag is set to true and
       send_q will not be affected by send() anymore.
       do not forget to avoid double mutex unlock in places where close() is called
    */
    sock_mut.unlock();

    while(!orig_send_q.empty()) {

        msg_buf* msg = orig_send_q.front();
        orig_send_q.pop_front();

        sip_msg s_msg(msg->msg,msg->msg_len);
        delete msg;

        copy_peer_addr(&s_msg.remote_ip);
        copy_addr_to(&s_msg.local_ip);
        s_msg.transport_id = get_transport_proto_id();

        trans_layer::instance()->transport_error(&s_msg);
    }
}

void tls_trsp_socket::pre_write()
{
    /*DBG("pre_write(): tls_connected:%d, senq_q.size():%zd, orig_send_q.size():%zd",
        tls_connected, send_q.size(),orig_send_q.size());*/

    try {
        if(tls_connected && !orig_send_q.empty()) {
            msg_buf* msg = orig_send_q.front();
            tls_channel->send((const uint8_t*)msg->cursor, msg->bytes_left());
            msg->cursor += msg->msg_len;
        }
    } catch(Botan::Exception& exc) {
      ERROR("unforseen error in tls: close connection (%s)",
                      exc.what());
      close();
    }
}

void tls_trsp_socket::post_write()
{
    /*DBG("post_write(): tls_connected:%d, senq_q.size():%zd, orig_send_q.size():%zd",
        tls_connected, send_q.size(),orig_send_q.size());*/
    if(tls_connected) {
        if(send_q.empty()) {
            msg_buf* msg = 0;
            while(!orig_send_q.empty()) {
                msg = orig_send_q.front();
                if(msg->bytes_left() == 0) {
                    orig_send_q.pop_front();
                    delete msg;
                } else {
                    break;
                }
            }
        }
        if(!orig_send_q.empty()) {
            add_write_event();
            DBG("write event added...");
        }
    }
}

void tls_trsp_socket::copy_peer_addr(sockaddr_storage* sa)
{
    if(tls_connected) {
        sockaddr_ssl* sa_ssl = (sockaddr_ssl*)sa;
        sa_ssl->ssl_marker = true;

        auto cipherst_optional = Botan::TLS::Ciphersuite::by_id(ciphersuite);
        if(cipherst_optional.has_value()) {
            auto &cipherst = cipherst_optional.value();
            for(int i = sockaddr_ssl::SIG_SHA; i <= sockaddr_ssl::SIG_RSA; i++) {
                if(toString((sockaddr_ssl::sig_method)i) == cipherst.kex_algo()) {
                    sa_ssl->sig = (sockaddr_ssl::sig_method)i;
                }
            }
            for(int i = sockaddr_ssl::CIPHER_AES256_OCB12; i <= sockaddr_ssl::CIPHER_3DES; i++) {
                if(toString((sockaddr_ssl::cipher_method)i) == cipherst.cipher_algo()) {
                    sa_ssl->cipher = (sockaddr_ssl::cipher_method)i;
                }
            }
            for(int i = sockaddr_ssl::MAC_AEAD; i <= sockaddr_ssl::MAC_SHA1; i++) {
                if(toString((sockaddr_ssl::mac_method)i) == cipherst.mac_algo()) {
                    sa_ssl->mac = (sockaddr_ssl::mac_method)i;
                }
            }
        }
    }

    return tcp_base_trsp::copy_peer_addr(sa);
}

void tls_trsp_socket::tls_emit_data(std::span<const uint8_t> data)
{
    send_q.push_back(new msg_buf(&peer_addr,(char*)data.data(),data.size()));

    if(connected) {
        add_write_event();
        DBG("write event added...");
    }
}

void tls_trsp_socket::tls_record_received([[maybe_unused]] uint64_t seq_no, std::span<const uint8_t> data)
{
    static_cast<tls_input*>(input)->on_tls_record(this, data.data(), data.size());
}

void tls_trsp_socket::tls_alert([[maybe_unused]] Botan::TLS::Alert alert)
{}

void tls_trsp_socket::tls_session_established(const Botan::TLS::Session_Summary& session)
{
    DBG("************ on_tls_connect() ***********");
    DBG("new TLS connection from %s:%u",
        get_peer_ip().c_str(),
        get_peer_port());

    tls_server_socket::tls_statistics* tls_stats = dynamic_cast<tls_server_socket::tls_statistics*>(server_sock->get_statistics());
    if(tls_stats) tls_stats->incTlsConnected(is_client());

    tls_connected = true;
    ciphersuite = session.ciphersuite_code();
    copy_peer_addr(&peer_addr);
    sockaddr_ssl* sa_ssl = reinterpret_cast<sockaddr_ssl*>(&peer_addr);

    DBG("ssl_marker:%d sig:%d cipher:%d mac:%d", sa_ssl->ssl_marker, sa_ssl->sig, sa_ssl->cipher, sa_ssl->mac);

    add_write_event();
    DBG("write event added...");
}

void tls_trsp_socket::tls_verify_cert_chain(
    const std::vector<Botan::X509_Certificate>& cert_chain,
    const std::vector<std::optional<Botan::OCSP::Response>>& ocsp_responses,
    const std::vector<Botan::Certificate_Store*>& trusted_roots,
    Botan::Usage_Type usage,
    std::string_view hostname,
    const Botan::TLS::Policy& policy)
{
    if((settings->s_client &&
        !settings->s_client->verify_certificate_chain &&
        !settings->s_client->verify_certificate_cn) ||
       (settings->s_server &&
        !settings->s_server->verify_client_certificate))
    {
        return;
    }

    if(settings->s_client &&
       settings->s_client->verify_certificate_cn)
    {
        if(settings->s_client->verify_certificate_chain) {
            if(!cert_chain[0].matches_dns_name(hostname))
                throw Botan::TLS::TLS_Exception(Botan::TLS::AlertType::BadCertificateStatusResponse, "Verify common name certificate failed");
        } else
            Botan::TLS::Callbacks::tls_verify_cert_chain(cert_chain, ocsp_responses, trusted_roots, usage, "", policy);
    } else
        Botan::TLS::Callbacks::tls_verify_cert_chain(cert_chain, ocsp_responses, trusted_roots, usage, hostname, policy);
}

int tls_trsp_socket::send(
    const sockaddr_storage* sa, const char* msg,
    const int msg_len, [[maybe_unused]] unsigned int flags)
{
    std::unique_lock _l(sock_mut);

    if(closed || (check_connection() < 0))
        return -1;

    DBG("add msg to send deque/from %s:%i to %s:%i\n--++--\n%.*s--++--",
        actual_ip.c_str(), actual_port,
        get_addr_str(sa).c_str(),
        am_get_port(sa),
        msg_len,msg);

    orig_send_q.push_back(new msg_buf(sa,msg,msg_len));

    if(connected) {
        add_write_event();
        DBG("write event added...");
    }

    return 0;
}

void tls_trsp_socket::getInfo(AmArg& ret)
{
    sockaddr_ssl* ssl = (sockaddr_ssl*)&peer_addr;
    ret["ssl_sig"] = toString(ssl->sig);
    ret["ssl_cipher"] = toString(ssl->cipher);
    ret["ssl_mac"] = toString(ssl->mac);
    ret["tls_queue_size"] = orig_send_q.size();
    tcp_base_trsp::getInfo(ret);
}

tls_socket_factory::tls_socket_factory(tcp_base_trsp::socket_transport transport)
  : trsp_socket_factory(transport)
{}

tcp_base_trsp* tls_socket_factory::create_socket(trsp_server_socket* server_sock, trsp_worker* server_worker, int sd, const sockaddr_storage* sa, event_base* evbase)
{
    try {
        return new tls_trsp_socket(server_sock, server_worker, sd, sa, transport, evbase);
    } catch(Botan::Exception& ex) {
        ERROR("Botan tls error: %s", ex.what());
        return 0;
    }
}

tls_server_socket::tls_server_socket(
    unsigned short if_num, unsigned short proto_idx,
    unsigned int opts, socket_transport transport)
  : trsp_server_socket(if_num, proto_idx, opts, new tls_socket_factory(transport), new tls_statistics(transport, if_num, proto_idx))
{}

tls_server_socket::tls_statistics::tls_statistics(trsp_socket::socket_transport transport, unsigned short if_num, unsigned short proto_idx)
: tcp_server_socket::tcp_statistics(transport, if_num, proto_idx)
, tlsInConnectedCount(stat_group(Gauge, "core", "connections").addAtomicCounter()
            .addLabel("direction", "in")
            .addLabel("state", "tls_connected")
            .addLabel("interface", AmConfig.sip_ifs[if_num].name)
            .addLabel("transport", trsp_socket::socket_transport2proto_str(transport))
            .addLabel("protocol", AmConfig.sip_ifs[if_num].proto_info[proto_idx]->ipTypeToStr()))
, tlsOutConnectedCount(stat_group(Gauge, "core", "connections").addAtomicCounter()
            .addLabel("direction", "out")
            .addLabel("state", "tls_connected")
            .addLabel("interface", AmConfig.sip_ifs[if_num].name)
            .addLabel("transport", trsp_socket::socket_transport2proto_str(transport))
            .addLabel("protocol", AmConfig.sip_ifs[if_num].proto_info[proto_idx]->ipTypeToStr())){}

void tls_server_socket::tls_statistics::changeCountConnection(bool remove, tcp_base_trsp* socket)
{
    tls_trsp_socket* tls_socket = dynamic_cast<tls_trsp_socket*>(socket);
    assert(tls_socket);
    if(remove && tls_socket->is_tls_connected()) {
        if(socket->is_client())
            tlsOutConnectedCount.dec();
        else
            tlsInConnectedCount.dec();
    } else {
        tcp_server_socket::tcp_statistics::changeCountConnection(remove, socket);
    }
}

void tls_server_socket::tls_statistics::incTlsConnected(bool is_client)
{
    if(is_client) {
        tlsOutConnectedCount.inc();
        clientOutConnectedCount.dec();
    } else {
        tlsInConnectedCount.inc();
        clientInConnectedCount.dec();
    }
}

void tls_cleanup()
{
    session_manager_tls::dispose();
}

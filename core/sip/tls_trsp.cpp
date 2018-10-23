#include "tls_trsp.h"
#include "trans_layer.h"

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

tls_conf::tls_conf(tls_client_settings* settings)
: s_client(settings), s_server(0)
, certificate(settings->certificate)
, key(Botan::PKCS8::load_key(settings->certificate_key, *rand_generator::instance()))
{
}

tls_conf::tls_conf(tls_server_settings* settings)
: s_client(0), s_server(settings)
, certificate(settings->certificate)
, key(Botan::PKCS8::load_key(settings->certificate_key, *rand_generator::instance()))
{
}

tls_conf::tls_conf(const tls_conf& conf)
: s_client(conf.s_client), s_server(conf.s_server)
, certificate(conf.certificate)
{
    if(conf.s_server) {
        key = std::unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(conf.s_server->certificate_key, *rand_generator::instance()));
    } else if(conf.s_client) {
        key = std::unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(conf.s_client->certificate_key, *rand_generator::instance()));
    }
}

vector<string> tls_conf::allowed_ciphers() const
{
    if(s_client) {
        return s_client->cipher_list;
    } else if(s_server) {
        return Policy::allowed_ciphers();
    }
    ERROR("allowed_ciphers: called in unexpected context");
    return vector<string>();
}

bool tls_conf::allow_tls10()  const
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
        if(proto == tls_client_settings::TLSv1) {
            return true;
        }
    }

    return false;
}

bool tls_conf::allow_tls11()  const
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
        if(proto == tls_client_settings::TLSv1_1) {
            return true;
        }
    }

    return false;
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

vector<Botan::Certificate_Store*> tls_conf::trusted_certificate_authorities(const string& type, const string& context)
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

    vector<Botan::Certificate_Store*> ca;
    for(auto& cert : settings->ca_list) {
        ca.push_back(new Botan::Certificate_Store_In_Memory(Botan::X509_Certificate(cert)));
    }

    return ca;
}

vector<Botan::X509_Certificate> tls_conf::cert_chain(const vector<string>& cert_key_types, const string& type, const string& context)
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

Botan::Private_Key* tls_conf::private_key_for(const Botan::X509_Certificate& cert, const string& type, const string& context)
{
    if(key) {
        return &*key;
    }
    return nullptr;
}

tls_trsp_socket::tls_trsp_socket(trsp_server_socket* server_sock,
				 trsp_server_worker* server_worker,
				 int sd, const sockaddr_storage* sa,
                 trsp_socket::socket_transport transport, struct event_base* evbase)
  : tcp_base_trsp(server_sock, server_worker, sd, sa, transport, evbase), tls_connected(false), orig_input_len(0)
{
    if(sd == -1) {
        settings = &static_cast<tls_server_socket*>(server_sock)->client_settings;
        tls_channel = new Botan::TLS::Client(*this, *session_manager::instance(), *settings, *settings,*rand_generator::instance(),
                                            Botan::TLS::Server_Information(get_peer_ip().c_str(), get_peer_port()),
                                            Botan::TLS::Protocol_Version::TLS_V12);
    } else {
        settings = &static_cast<tls_server_socket*>(server_sock)->server_settings;
        tls_channel = new Botan::TLS::Server(*this, *session_manager::instance(), *settings, *settings,*rand_generator::instance(), false);
    }
}

tls_trsp_socket::~tls_trsp_socket()
{
    if(tls_channel) {
        delete tls_channel;
    }
}

int tls_trsp_socket::on_input()
{
    try {
        int ret = tls_channel->received_data(orig_input_buf, orig_input_len);
        reset_input();
        return ret;
    } catch(Botan::Exception& ex) {
        ERROR("Botan tls error: %s", ex.what());
        return -1;
    }
}

void tls_trsp_socket::tls_emit_data(const uint8_t data[], size_t size)
{
    send_q.push_back(new msg_buf(&peer_addr,(char*)data,size));

    if(connected) {
        add_write_event();
        DBG("write event added...");
    }
}

void tls_trsp_socket::tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size)
{
    memcpy(input_buf, data, size);
    tcp_base_trsp::add_input_len(size);
    parse_input();
    reset_input();
}

void tls_trsp_socket::tls_alert(Botan::TLS::Alert alert)
{
}

bool tls_trsp_socket::tls_session_established(const Botan::TLS::Session& session)
{
    tls_connected = true;
    while(!orig_send_q.empty()) {
        msg_buf* msg = orig_send_q.front();
        send_q.push_back(msg);
        orig_send_q.pop_front();
    }
    /* doc: https://botan.randombit.net/manual/tls.html
     * If this function returns false, the session will not be cached for later resumption.
     */
    return true;
}

int tls_trsp_socket::send(const sockaddr_storage* sa, const char* msg,
	   const int msg_len, unsigned int flags)
{
  AmLock _l(sock_mut);

  if(closed || (check_connection() < 0))
    return -1;

  DBG("add msg to send deque/from %s:%i to %s:%i\n--++--\n%.*s--++--\n",
            actual_ip.c_str(), actual_port,
            get_addr_str(sa).c_str(),
            am_get_port(sa),
            msg_len,msg);

  if(tls_connected) {
    tls_channel->send((const uint8_t*)msg, msg_len);
  } else {
    orig_send_q.push_back(new msg_buf(sa,msg,msg_len));
  }

  if(connected) {
    add_write_event();
    DBG("write event added...");
  }

  return 0;
}

tls_socket_factory::tls_socket_factory(tcp_base_trsp::socket_transport transport)
 : trsp_socket_factory(transport){}

tcp_base_trsp* tls_socket_factory::create_socket(trsp_server_socket* server_sock, trsp_server_worker* server_worker,
                                                int sd, const sockaddr_storage* sa, event_base* evbase)
{
    try {
        return new tls_trsp_socket(server_sock, server_worker, sd, sa, transport, evbase);
    } catch(Botan::Exception& ex) {
        ERROR("Botan tls error: %s", ex.what());
        return 0;
    }
}

tls_server_socket::tls_server_socket(unsigned short if_num, unsigned short addr_num,
                                     unsigned int opts, socket_transport transport,
                                     const tls_conf& s_client,
                                     const tls_conf& s_server)
: trsp_server_socket(if_num, addr_num, opts, new tls_socket_factory(transport))
, client_settings(s_client), server_settings(s_server)
{
}


tls_trsp::tls_trsp(trsp_server_socket* sock, trsp_acl &acl, trsp_acl &opt_acl)
    : transport(sock, acl, opt_acl)
{
  evbase = event_base_new();
  sock->add_event(evbase);
}

tls_trsp::~tls_trsp()
{
  if(evbase) {
    event_base_free(evbase);
  }
}

/** @see AmThread */
void tls_trsp::run()
{
  int server_sd = sock->get_sd();
  if(server_sd <= 0){
    ERROR("Transport instance not bound\n");
    return;
  }

  trsp_server_socket* tcp_sock = static_cast<trsp_server_socket*>(sock);
  tcp_sock->start_threads();

  INFO("Started SIP server TLS transport on %s:%i\n",
       sock->get_ip(),sock->get_port());

  setThreadName("sip-tls-trsp");

  /* Start the event loop. */
  int ret = event_base_dispatch(evbase);

  INFO("TLS SIP server on %s:%i finished (%i)",
       sock->get_ip(),sock->get_port(),ret);
}

/** @see AmThread */
void tls_trsp::on_stop()
{
  event_base_loopbreak(evbase);
  trsp_server_socket* tcp_sock = static_cast<trsp_server_socket*>(sock);
  tcp_sock->stop_threads();
  join();
}

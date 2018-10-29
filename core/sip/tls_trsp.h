#ifndef _tls_trsp_h_
#define _tls_trsp_h_

#include "singleton.h"
#include "transport.h"
#include "tcp_base_trsp.h"
#include "sip_parser_async.h"
#include "tls_trsp_settings.h"

#include <vector>
using std::vector;

#include <sys/socket.h>
#include <event2/event.h>

#include <map>
#include <deque>
#include <string>
using std::map;
using std::deque;
using std::string;

#include <botan/auto_rng.h>
#include <botan/tls_policy.h>
#include <botan/tls_channel.h>
#include <botan/tls_callbacks.h>
#include <botan/credentials_manager.h>

class tls_conf : public Botan::TLS::Policy, public Botan::Credentials_Manager
{
    friend class tls_trsp_socket;
    tls_client_settings* s_client;
    tls_server_settings* s_server;
    Botan::X509_Certificate certificate;
    std::unique_ptr<Botan::Private_Key> key;
public:
    tls_conf(tls_client_settings* settings);
    tls_conf(tls_server_settings* settings);
    tls_conf(const tls_conf& conf);

    //Policy functions
    vector<string> allowed_ciphers() const override;
    vector<string> allowed_macs() const override;
    bool allow_tls10()  const override;
    bool allow_tls11()  const override;
    bool allow_tls12()  const override;
    bool allow_dtls10() const override { return false;}
    bool allow_dtls12() const override { return false;}
    bool require_cert_revocation_info() const override { return false; }

    //Credentials_Manager functions
    vector<Botan::Certificate_Store*> trusted_certificate_authorities(const string& type, const string& context) override;
    vector<Botan::X509_Certificate> cert_chain(const vector<string>& cert_key_types, const string& type, const string& context) override;
    Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert, const string& type, const string& context) override;
};

class tls_rand_generator
{
public:
    Botan::AutoSeeded_RNG rng;
    operator Botan::RandomNumberGenerator& () {
        return rng;
    }
};

typedef singleton<tls_rand_generator> rand_generator;

class tls_session_manager
{
public:
    Botan::TLS::Session_Manager_In_Memory ssm;
    tls_session_manager() : ssm(*rand_generator::instance()){}
    operator Botan::TLS::Session_Manager_In_Memory& () {
        return ssm;
    }
};

typedef singleton<tls_session_manager> session_manager;

class tls_trsp_socket: public tcp_base_trsp, public Botan::TLS::Callbacks
{
    bool tls_connected;
    deque<msg_buf*> orig_send_q;

    unsigned char    orig_input_buf[MAX_TCP_MSGLEN];
    int              orig_input_len;

    Botan::TLS::Channel* tls_channel;
    tls_conf* settings;

    unsigned char*   get_input() { return orig_input_buf + orig_input_len; }
    int              get_input_free_space() {
        if(orig_input_len > MAX_TCP_MSGLEN) return 0;
        return MAX_TCP_MSGLEN - orig_input_len;
    }
    virtual void reset_input() {
        orig_input_len = 0;
    }

    friend class tls_socket_factory;
    const char* get_transport() const { return "tls"; }
    tls_trsp_socket(trsp_server_socket* server_sock, trsp_server_worker* server_worker, int sd,
                  const sockaddr_storage* sa, socket_transport transport, event_base* evbase);

    void tls_emit_data(const uint8_t data[], size_t size);
    void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size);
    void tls_alert(Botan::TLS::Alert alert);
    bool tls_session_established(const Botan::TLS::Session& session);
    void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>& cert_chain,
                                const std::vector<std::shared_ptr<const Botan::OCSP::Response>>& ocsp_responses,
                                const std::vector<Botan::Certificate_Store*>& trusted_roots,
                                Botan::Usage_Type usage,
                                const std::string& hostname,
                                const Botan::TLS::Policy& policy);
public:
    virtual ~tls_trsp_socket();

    int on_input();
    void add_input_len(int len){
        orig_input_len += len;
    }

    int send(const sockaddr_storage* sa, const char* msg,
	   const int msg_len, unsigned int flags);
};

class tls_socket_factory : public trsp_socket_factory
{
public:
    tls_socket_factory(tcp_base_trsp::socket_transport transport);

    tcp_base_trsp* create_socket(trsp_server_socket* server_sock, trsp_server_worker* server_worker,
                                         int sd, const sockaddr_storage* sa, event_base* evbase);
};

class tls_server_socket : public trsp_server_socket
{
public:
    tls_server_socket(unsigned short if_num, unsigned short addr_num,
                      unsigned int opts, socket_transport transport,
                      const tls_conf& s_client,
                      const tls_conf& s_server);

    const char* get_transport() const { return "tls"; }

    tls_conf client_settings;
    tls_conf server_settings;
};

class tls_trsp: public transport
{
  struct event_base *evbase;

protected:
  /** @see AmThread */
  void run();
  /** @see AmThread */
  void on_stop();

public:
  /** @see transport */
  tls_trsp(trsp_server_socket* sock, trsp_acl &acl, trsp_acl &opt_acl);
  ~tls_trsp();
};

#endif/*_tls_trsp_h_*/

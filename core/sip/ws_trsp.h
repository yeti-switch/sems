#ifndef _ws_trsp_h_
#define _ws_trsp_h_

#include "transport.h"
#include "tcp_trsp.h"
#include "tls_trsp.h"
#include "sip_parser_async.h"

#include <vector>
using std::vector;

/**
 * Maximum message length for TCP
 * not including terminating '\0'
 */
#define MAX_TCP_MSGLEN 65535

#include <sys/socket.h>
#include <event2/event.h>
#include <wslay/wslay.h>

#include <map>
#include <deque>
#include <string>
using std::map;
using std::deque;
using std::string;

class msg_buf;

class ws_output
{
public:
    ws_output(){}
    virtual ~ws_output(){}
    virtual int send_data(const char* msg, const int msg_len, unsigned int flags)=0;
    virtual int send(const char* msg, const int msg_len, unsigned int flags)=0;
    virtual cstring get_host() = 0;
    virtual void on_ws_connected() = 0;
    virtual void on_ws_close() = 0;
    virtual void copy_addrs(
        sockaddr_storage* sa_local, sockaddr_storage* sa_remote,
        unsigned int &protocol_id) = 0;
};

class ws_input : public trsp_base_input
{
    unsigned char    ws_input_buf[MAX_TCP_MSGLEN];
    size_t           ws_input_len;
    size_t           ws_input_pos;
    cstring          ws_accept;
    cstring          ws_key;

    AmMutex sock_mut;
    deque<tcp_base_trsp::msg_buf*> send_q;

protected:
    bool ws_connected;
    bool is_server;
    ws_output* output;
    wslay_event_context_ptr ctx_;

    static struct wslay_event_callbacks callbacks;
    static ssize_t recv_callback(wslay_event_context_ptr ctx, uint8_t *data, size_t len, int flags, void *user_data);
    static void on_msg_recv_callback(wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg *arg, void *user_data);
    static ssize_t send_callback(wslay_event_context_ptr ctx, const uint8_t *data, size_t len, int flags, void *user_data);
    static int genmask_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, void *user_data);
    ssize_t recv_callback(wslay_event_context_ptr ctx, uint8_t *data, size_t len, int flags);
    void on_msg_recv(wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg *arg);
    ssize_t on_send_callback(wslay_event_context_ptr ctx, const uint8_t *data, size_t len, int flags);

    cstring get_sec_ws_accept_data(const cstring& key);
    cstring get_sec_ws_key_data();
    int send_reply(sip_msg* req, int reply_code, const cstring& reason);
    int send_request();
public:
    ws_input(ws_output* output, bool server);
    virtual ~ws_input();

    void pre_write();
    void post_write();
    int send(tcp_base_trsp::msg_buf* buf);
    void generate_transport_errors();

    unsigned char*   get_input();
    int get_input_free_space();
    void reset_input();
    void add_input_len(int len);
    int on_input(tcp_base_trsp* trsp);
    void on_parsed_received_msg(tcp_base_trsp* trsp, sip_msg* s_msg);

    bool is_connected() {
        return ws_connected;
    }
};

class wss_input : public tls_input
{
    ws_input input;
public:
    wss_input(ws_output* output, bool server)
    : input(output, server){}
    int on_tls_record(tcp_base_trsp* trsp, const uint8_t data[], size_t size);

    void pre_write();
    void post_write();
    int send(tcp_base_trsp::msg_buf* buf);
    void generate_transport_errors();
    bool is_connected();
};

class ws_trsp_socket: public ws_output, public tcp_trsp_socket
{
    //bool ws_connected;
    friend class ws_socket_factory;
    const char* get_transport() const { return "ws"; }
    int send_data(const char* msg, const int msg_len, unsigned int flags);
    int send(const char* msg, const int msg_len, unsigned int flags) {
        return tcp_trsp_socket::send(&peer_addr, msg, msg_len, flags);
    }

    cstring get_host() {
        return cstring(get_peer_ip().c_str(), get_peer_ip().size());
    }

    virtual void copy_addrs(
        sockaddr_storage* sa_local, sockaddr_storage* sa_remote,
        unsigned int &protocol_id)
    {
        copy_peer_addr(sa_remote);
        copy_addr_to(sa_local);
        protocol_id = get_transport_proto_id();
    }

    void generate_transport_errors();

protected:
    void on_ws_connected();
    void on_ws_close();

    ws_trsp_socket(trsp_server_socket* server_sock, trsp_worker* server_worker, int sd,
                    const sockaddr_storage* sa, socket_transport transport, event_base* evbase);
public:
    ~ws_trsp_socket();

    void pre_write();
    void post_write();
    int send(const sockaddr_storage* sa, const char* msg, const int msg_len, unsigned int flags);
};

class wss_trsp_socket: public ws_output, public tls_trsp_socket
{

    friend class wss_socket_factory;
    const char* get_transport() const { return "wss"; }
    wss_trsp_socket(trsp_server_socket* server_sock, trsp_worker* server_worker, int sd,
                  const sockaddr_storage* sa, socket_transport transport, event_base* evbase);

    int send_data(const char* msg, const int msg_len, unsigned int flags);
    int send(const char* msg, const int msg_len, unsigned int flags) {
        return tls_trsp_socket::send(&peer_addr, msg, msg_len, flags);
    }
    cstring get_host() {
        return cstring(get_peer_ip().c_str(), get_peer_ip().size());
    }

    virtual void copy_addrs(
        sockaddr_storage* sa_local, sockaddr_storage* sa_remote,
        unsigned int &protocol_id)
    {
        copy_peer_addr(sa_remote);
        copy_addr_to(sa_local);
        protocol_id = get_transport_proto_id();
    }

    void generate_transport_errors();

    void on_ws_connected();
    void on_ws_close();
public:
    ~wss_trsp_socket();

    void pre_write();
    void post_write();
    int send(const sockaddr_storage* sa, const char* msg, const int msg_len, unsigned int flags);
};

class wss_socket_factory : public trsp_socket_factory
{
public:
    wss_socket_factory(tcp_base_trsp::socket_transport transport);

    tcp_base_trsp* create_socket(trsp_server_socket* server_sock, trsp_worker* server_worker,
                                         int sd, const sockaddr_storage* sa, event_base* evbase);
};

class ws_socket_factory : public trsp_socket_factory
{
public:
    ws_socket_factory(tcp_base_trsp::socket_transport transport);

    tcp_base_trsp* create_socket(trsp_server_socket* server_sock, trsp_worker* server_worker,
                                         int sd, const sockaddr_storage* sa, event_base* evbase);
};

class ws_server_socket: public trsp_server_socket
{
public:
  ws_server_socket(unsigned short if_num, unsigned short proto_idx, unsigned int opts, socket_transport transport);

  const char* get_transport() const { return "ws"; }
};

class wss_server_socket: public trsp_server_socket
{
public:
  wss_server_socket(unsigned short if_num, unsigned short proto_idx, unsigned int opts, socket_transport transport);

  const char* get_transport() const { return "wss"; }
};

#endif/*_ws_trsp_h_*/

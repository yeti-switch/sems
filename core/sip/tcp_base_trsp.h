#ifndef _tcp_base_trsp_h_
#define _tcp_base_trsp_h_

#include "transport.h"
#include "sip_parser_async.h"

#include <map>
#include <string>
#include <deque>
using std::map;
using std::deque;
using std::string;

/**
 * Maximum message length for TCP
 * not including terminating '\0'
 */
#define MAX_TCP_MSGLEN 65535

#include <sys/socket.h>
#include <event2/event.h>

class trsp_server_socket;
class trsp_server_worker;

class tcp_base_trsp : public trsp_socket
{
protected:
    friend class trsp_socket_factory;
    trsp_server_socket* server_sock;
    trsp_server_worker* server_worker;

    bool             closed;
    bool             connected;
    sockaddr_storage peer_addr;
    string           peer_ip;
    unsigned short   peer_port;
    bool             peer_addr_valid;

    parser_state     pst;
    unsigned char    input_buf[MAX_TCP_MSGLEN];
    int              input_len;

    struct event_base* evbase;
    struct event*      read_ev;
    struct event*      write_ev;

    struct msg_buf {
        sockaddr_storage addr;
        char*            msg;
        int              msg_len;
        char*            cursor;

        msg_buf(const sockaddr_storage* sa, const char* msg,
            const int msg_len);
        ~msg_buf();

        int bytes_left() { return msg_len - (cursor - msg); }
    };

    AmMutex sock_mut;
    deque<msg_buf*> send_q;

    virtual unsigned char*   get_input() { return input_buf + input_len; }
    virtual int              get_input_free_space() {
        if(input_len > MAX_TCP_MSGLEN) return 0;
        return MAX_TCP_MSGLEN - input_len;
    }
    virtual void add_input_len(int len){
        input_len += len;
    }
    virtual void reset_input() {
        input_len = 0;
    }

    int parse_input();

    /** fake implementation: we will never bind a connection socket */
    int bind(const string& address, unsigned short port) {
        return 0;
    }

    /**
    * Closes the connection/socket
    *
    * Warning: never do anything with the object
    *          after close as it could have been
    *          destroyed.
    */
    void close();

    /**
    * Generates a transport error for each request
    * left in send queue.
    */
    void generate_transport_errors();

    /**
    * Adds persistent read-event to event base.
    */
    void add_read_event();

    /**
    * Same as add_read_event() but unlock before
    * calling event_add().
    */
    void add_read_event_ul();

    /**
    * Adds one-shot write-event to event base.
    */
    void add_write_event(struct timeval* timeout=NULL);

    /**
    * Same as add_write_event() but unlock before
    * calling event_add().
    */
    void add_write_event_ul(struct timeval* timeout);

    /**
    * Instantiates read_ev & write_ev
    * Warning: call only ONCE!!!
    */
    void create_events();

    /*
    * Connects the socket to the destination
    * given in constructor.
    */
    int connect();

    /**
    * Checks whether or not the socket is already connected.
    * If not, a new connection will be tried.
    */
    int check_connection();



    int  on_connect(short ev);
    void on_write(short ev);
    void on_read(short ev);


    virtual int on_input() = 0;

    static void on_sock_read(int fd, short ev, void* arg);
    static void on_sock_write(int fd, short ev, void* arg);

    tcp_base_trsp(trsp_server_socket* server_sock, trsp_server_worker* server_worker, int sd,
                  const sockaddr_storage* sa, socket_transport transport, event_base* evbase);
    virtual ~tcp_base_trsp();

public:
    bool        is_reliable() const   { return true; }
    void copy_peer_addr(sockaddr_storage* sa);

    const string& get_peer_ip() {
        return peer_ip;
    }

    unsigned short get_peer_port() {
        return peer_port;
    }

    bool is_connected() {
        return connected;
    }

    void getInfo(AmArg &ret);
};

class trsp_socket_factory
    : public atomic_ref_cnt
{
protected:
    trsp_socket_factory(tcp_base_trsp::socket_transport transport)
        : transport(transport){}
public:
    virtual ~trsp_socket_factory(){}

    void create_connected(trsp_server_socket* server_sock,
                    trsp_server_worker* server_worker,
                    int sd, const sockaddr_storage* sa,
                    struct event_base* evbase);

    tcp_base_trsp* new_connection(trsp_server_socket* server_sock,
                        trsp_server_worker* server_worker,
                        const sockaddr_storage* sa,
                        struct event_base* evbase);

    virtual tcp_base_trsp* create_socket(trsp_server_socket* server_sock, trsp_server_worker* server_worker, int sd,
                                        const sockaddr_storage* sa, event_base* evbase) = 0;

    tcp_base_trsp::socket_transport transport;
};

class trsp_server_worker
  : public AmThread
{
    struct event_base* evbase;
    trsp_server_socket* server_sock;
    trsp_socket_factory* sock_factory;

    AmMutex                      connections_mut;
    map<string,tcp_base_trsp*> connections;

protected:
    void run();
    void on_stop();

public:
    trsp_server_worker(trsp_server_socket* server_sock, trsp_socket_factory* sock_factory);
    ~trsp_server_worker();

    int send(const sockaddr_storage* sa, const char* msg,
        const int msg_len, unsigned int flags);

    void add_connection(tcp_base_trsp* client_sock);
    void remove_connection(tcp_base_trsp* client_sock);
    void getInfo(AmArg &ret);
};

class trsp_server_socket : public trsp_socket
{
protected:
    struct event_base* evbase;
    struct event*      ev_accept;
    trsp_socket_factory* sock_factory;

    vector<trsp_server_worker*> workers;

    /**
    * Timeout while connecting to a remote peer.
    */
    struct timeval connect_timeout;

    /**
    * Idle Timeout before closing a connection.
    */
    struct timeval idle_timeout;

    /* callback on new connection */
    void on_accept(int sd, short ev);

    /* libevent callback on new connection */
    static void on_accept(int sd, short ev, void* arg);

    static uint32_t hash_addr(const sockaddr_storage* addr);

    trsp_server_socket(unsigned short if_num, unsigned short addr_num, unsigned int opts, trsp_socket_factory* sock_factory);
    ~trsp_server_socket();

public:
    void add_threads(unsigned int n);
    void start_threads();
    void stop_threads();

    bool        is_reliable() const   { return true; }

    /* activates libevent on_accept callback */
    void add_event(struct event_base *evbase);

    int bind(const string& address, unsigned short port);
    int send(const sockaddr_storage* sa, const char* msg,
        const int msg_len, unsigned int flags);

    /**
    * Set timeout in milliseconds for the connection
    * establishement handshake.
    */
    void set_connect_timeout(unsigned int ms);

    /**
    * Set idle timeout in milliseconds for news connections.
    * If during this period of time no packet is received,
    * the connection will be closed.
    */
    void set_idle_timeout(unsigned int ms);

    struct timeval* get_connect_timeout();
    struct timeval* get_idle_timeout();

    void getInfo(AmArg &ret);
};

#endif/*_tcp_base_trsp_h_*/

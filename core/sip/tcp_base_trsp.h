#ifndef _tcp_base_trsp_h_
#define _tcp_base_trsp_h_

#include "transport.h"
#include "sip_parser_async.h"

#include <mutex>
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
class trsp_worker;
class tcp_base_trsp;
struct sip_msg;

struct trsp_input
{
    trsp_input(){}
    virtual ~trsp_input(){}

    virtual void on_parsed_received_msg(tcp_base_trsp* socket, sip_msg* s_msg) = 0;
    virtual unsigned char* get_input() = 0;
    virtual int get_input_free_space() = 0;
    virtual void add_input_len(int len) = 0;
    virtual int on_input(tcp_base_trsp* socket) = 0;
};

class trsp_base_input : public trsp_input
{
    unsigned char    input_buf[MAX_TCP_MSGLEN];
    int              input_len;
    parser_state     pst;

public:
    trsp_base_input();
    virtual ~trsp_base_input(){}
    unsigned char*   get_input() override { return input_buf + input_len; }
    int              get_input_free_space() override {
        if(input_len > MAX_TCP_MSGLEN) return 0;
        return MAX_TCP_MSGLEN - input_len;
    }
    void add_input_len(int len) override{
        input_len += len;
    }

    void reset_input() {
        input_len = 0;
    }
    void on_parsed_received_msg(tcp_base_trsp* socket, sip_msg* s_msg) override;
    int parse_input(tcp_base_trsp* socket);

    // parse_input dbg fields
    int last_parse_input_ret;
    std::list<int> last_parse_input_messages_size;
};

class tcp_base_trsp : public trsp_socket
{
  protected:
    friend class trsp_worker;
    friend class trsp_base_input;
    trsp_server_socket* server_sock;
    trsp_worker* server_worker;
    trsp_input* input;

    bool             closed;
    bool             connected;
    sockaddr_storage peer_addr;
    string           peer_ip;
    unsigned short   peer_port;
    bool             peer_addr_valid;

    struct event_base* evbase;
    struct event*      read_ev;
    struct event*      write_ev;

public:
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

protected:
    std::mutex sock_mut;
    deque<msg_buf*> send_q;


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
    virtual void generate_transport_errors();

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


    virtual int on_connect(short ev);
    void on_write(short ev);
    void on_read(short ev);

    virtual void pre_write(){}
    virtual void post_write(){}

    static void on_sock_read(int fd, short ev, void* arg);
    static void on_sock_write(int fd, short ev, void* arg);

    tcp_base_trsp(trsp_server_socket* server_sock, trsp_worker* server_worker, int sd,
                  const sockaddr_storage* sa, socket_transport transport, event_base* evbase, trsp_input* input);
    virtual ~tcp_base_trsp();

public:
    bool        is_reliable() const   { return true; }
    virtual void copy_peer_addr(sockaddr_storage* sa);

    const string& get_peer_ip() {
        return peer_ip;
    }

    unsigned short get_peer_port() {
        return peer_port;
    }

    bool is_connected() {
        return connected;
    }

    virtual void set_connected(bool val);

    void getInfo(AmArg &ret);
    unsigned long long getQueueSize();
};

class trsp_socket_factory
    : public atomic_ref_cnt
{
protected:
    trsp_socket_factory(tcp_base_trsp::socket_transport transport)
        : transport(transport){}
public:
    virtual ~trsp_socket_factory(){}

    tcp_base_trsp* new_connection(trsp_server_socket* server_sock,
                        trsp_worker* server_worker, int sd,
                        const sockaddr_storage* sa,
                        struct event_base* evbase);

    virtual tcp_base_trsp* create_socket(trsp_server_socket* server_sock, trsp_worker* server_worker, int sd,
                                        const sockaddr_storage* sa, event_base* evbase) = 0;

    tcp_base_trsp::socket_transport transport;
};

class trsp_worker
  : public AmThread
{
    struct event_base* evbase;

    AmMutex                      connections_mut;
    map<string,tcp_base_trsp*>   connections;
    AmCondition<bool> stopped;

    template<class socket> unsigned long long getQueueSize();
protected:
    void run();
    void on_stop();

    friend class trsp_server_socket;
    void create_connected(trsp_server_socket* server_sock, int sd, const sockaddr_storage* sa);
    tcp_base_trsp* new_connection(trsp_server_socket* server_sock, const sockaddr_storage* sa);
public:
    trsp_worker();
    virtual ~trsp_worker();

    int send(trsp_server_socket* server_sock, const sockaddr_storage* sa, const char* msg,
        const int msg_len, unsigned int flags);
    
    void add_connection(tcp_base_trsp* client_sock);
    void remove_connection(tcp_base_trsp* client_sock);
    bool remove_connection(const string& ip, unsigned short port, unsigned short if_num);
    void getInfo(AmArg &ret);
    unsigned long long getTcpQueueSize();
    unsigned long long getTlsQueueSize();
    unsigned long long getWsQueueSize();
    unsigned long long getWssQueueSize();
};

class trsp_statistics
{
public:
    struct trsp_st_base
    {
        AtomicCounter& countOutPendingConnections;
        AtomicCounter& countInPendingConnections;
        AtomicCounter& sipParseErrors;
        trsp_st_base(trsp_socket::socket_transport transport, unsigned short if_num, unsigned short proto_idx);
        virtual ~trsp_st_base(){}
        virtual void changeCountConnection(bool remove, tcp_base_trsp* socket);
        void incPendingConnectionsCount(tcp_base_trsp* socket);
        void decPendingConnectionsCount(tcp_base_trsp* socket);
    };
private:
    vector<trsp_st_base*> stats;
public:
    void add_trsp_statistics(trsp_st_base* stream) {
        stats.push_back(stream);
    }
    void dispose() {
        for(auto stream : stats) delete stream;
    }
};

typedef singleton<trsp_statistics> stream_stats;

class trsp_server_socket : public trsp_socket
{
protected:
    std::map<string, string> labels;
    trsp_statistics::trsp_st_base* statistics;
    struct event_base* evbase;
    struct event*      ev_accept;

    friend class trsp_worker;
    trsp_socket_factory* sock_factory;
    vector<trsp_worker*> workers;

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

    trsp_server_socket(unsigned short if_num, unsigned short proto_idx, unsigned int opts, trsp_socket_factory* sock_factory, trsp_statistics::trsp_st_base* statistics);
    ~trsp_server_socket();

public:
    void add_workers(trsp_worker **trsp_workers, unsigned short n_trsp_workers);

    bool        is_reliable() const  override { return true; }

    /* activates libevent on_accept callback */
    void add_event(struct event_base *evbase);

    int bind(const string& address, unsigned short port) override;
    int send(const sockaddr_storage* sa, const char* msg,
        const int msg_len, unsigned int flags) override;

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

    void inc_sip_parse_error() override{ statistics->sipParseErrors.inc(); }
    trsp_statistics::trsp_st_base* get_statistics() { return statistics; }
    void getAcceptQueueSize(StatCounterInterface::iterate_func_type f);
};

class trsp: public AmThread
{
  struct event_base *evbase;

protected:
  /** @see AmThread */
  void run();
  /** @see AmThread */
  void on_stop();
  
public:
  /** @see transport */
  trsp();
  ~trsp();
  
  void add_socket(trsp_server_socket* sock);
};

#endif/*_tcp_base_trsp_h_*/

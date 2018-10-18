#ifndef _tcp_trsp_h_
#define _tcp_trsp_h_

#include "transport.h"
#include "tcp_base_trsp.h"
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

#include <map>
#include <deque>
#include <string>
using std::map;
using std::deque;
using std::string;

class tcp_server_socket;

class tcp_trsp_socket: public tcp_base_trsp
{

  friend class tcp_socket_factory;
  const char* get_transport() const { return "tcp"; }
  tcp_trsp_socket(trsp_server_socket* server_sock, trsp_server_worker* server_worker, int sd,
                  const sockaddr_storage* sa, socket_transport transport, event_base* evbase);

public:
  ~tcp_trsp_socket();

  int on_input();

  int send(const sockaddr_storage* sa, const char* msg,
	   const int msg_len, unsigned int flags);
};

class tcp_socket_factory : public trsp_socket_factory
{
public:
    tcp_socket_factory(tcp_base_trsp::socket_transport transport);

    tcp_base_trsp* create_socket(trsp_server_socket* server_sock, trsp_server_worker* server_worker,
                                         int sd, const sockaddr_storage* sa, event_base* evbase);
};

class tcp_server_socket: public trsp_server_socket
{
public:
  tcp_server_socket(unsigned short if_num, unsigned short addr_num, unsigned int opts, socket_transport transport);

  const char* get_transport() const { return "tcp"; }
};

class tcp_trsp: public transport
{
  struct event_base *evbase;

protected:
  /** @see AmThread */
  void run();
  /** @see AmThread */
  void on_stop();
    
public:
  /** @see transport */
  tcp_trsp(tcp_server_socket* sock, trsp_acl &acl, trsp_acl &opt_acl);
  ~tcp_trsp();
};

#endif

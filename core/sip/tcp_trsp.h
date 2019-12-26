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

class tcp_input : public trsp_base_input
{
public:
    int on_input(tcp_base_trsp * socket);
};

class tcp_trsp_socket: public tcp_base_trsp
{
  friend class tcp_socket_factory;
  tcp_trsp_socket(trsp_server_socket* server_sock, trsp_worker* server_worker, int sd,
                  const sockaddr_storage* sa, socket_transport transport, event_base* evbase);
protected:
  tcp_trsp_socket(trsp_server_socket* server_sock, trsp_worker* server_worker, int sd,
                  const sockaddr_storage* sa, socket_transport transport,
                  event_base* evbase, trsp_input* input);
  const char* get_transport() const { return "tcp"; }
public:
  ~tcp_trsp_socket();

  int send(const sockaddr_storage* sa, const char* msg,
	   const int msg_len, unsigned int flags);
};

class tcp_socket_factory : public trsp_socket_factory
{
public:
    tcp_socket_factory(tcp_base_trsp::socket_transport transport);

    tcp_base_trsp* create_socket(trsp_server_socket* server_sock, trsp_worker* server_worker,
                                         int sd, const sockaddr_storage* sa, event_base* evbase);
};

class tcp_server_socket: public trsp_server_socket
{
public:
  tcp_server_socket(unsigned short if_num, unsigned short proto_idx, unsigned int opts, socket_transport transport);

  const char* get_transport() const { return "tcp"; }
};

#endif/*_tcp_trsp_h_*/

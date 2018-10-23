#include "tcp_trsp.h"
#include "ip_util.h"
#include "parse_common.h"
#include "sip_parser.h"
#include "trans_layer.h"
#include "hash.h"
#include "parse_via.h"

#include "AmUtils.h"

#include <netdb.h>
#include <event2/event.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <AmLcConfig.h>

//avoid sockets in WAITING state. close() will send RST and immediately remove entry from hashtable
#define TCP_STATIC_CLIENT_PORT_CLOSE_NOWAIT 1


tcp_trsp_socket::tcp_trsp_socket(trsp_server_socket* server_sock,
				 trsp_server_worker* server_worker,
				 int sd, const sockaddr_storage* sa,
                 trsp_socket::socket_transport transport, struct event_base* evbase)
  : tcp_base_trsp(server_sock, server_worker, sd, sa, transport, evbase)
{
}

tcp_trsp_socket::~tcp_trsp_socket(){}

int tcp_trsp_socket::on_input()
{
    return parse_input();
}

int tcp_trsp_socket::send(const sockaddr_storage* sa, const char* msg, 
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

  send_q.push_back(new msg_buf(sa,msg,msg_len));

  if(connected) {
    add_write_event();
    DBG("write event added...");
  }

  return 0;
}

tcp_socket_factory::tcp_socket_factory(tcp_base_trsp::socket_transport transport)
 : trsp_socket_factory(transport){}

tcp_base_trsp* tcp_socket_factory::create_socket(trsp_server_socket* server_sock, trsp_server_worker* server_worker,
                                                int sd, const sockaddr_storage* sa, event_base* evbase)
{
    return new tcp_trsp_socket(server_sock, server_worker, sd, sa, transport, evbase);
}

tcp_server_socket::tcp_server_socket(short unsigned int if_num, short unsigned int addr_num, unsigned int opts, socket_transport transport)
: trsp_server_socket(if_num, addr_num, opts, new tcp_socket_factory(transport))
{
}

tcp_trsp::tcp_trsp(tcp_server_socket* sock, trsp_acl &acl, trsp_acl &opt_acl)
    : transport(sock, acl, opt_acl)
{
  evbase = event_base_new();
  sock->add_event(evbase);
}

tcp_trsp::~tcp_trsp()
{
  if(evbase) {
    event_base_free(evbase);
  }
}

/** @see AmThread */
void tcp_trsp::run()
{
  int server_sd = sock->get_sd();
  if(server_sd <= 0){
    ERROR("Transport instance not bound\n");
    return;
  }

  tcp_server_socket* tcp_sock = static_cast<tcp_server_socket*>(sock);
  tcp_sock->start_threads();

  INFO("Started SIP server TCP transport on %s:%i\n",
       sock->get_ip(),sock->get_port());

  setThreadName("sip-tcp-trsp");

  /* Start the event loop. */
  int ret = event_base_dispatch(evbase);

  INFO("TCP SIP server on %s:%i finished (%i)",
       sock->get_ip(),sock->get_port(),ret);
}

/** @see AmThread */
void tcp_trsp::on_stop()
{
  event_base_loopbreak(evbase);
  tcp_server_socket* tcp_sock = static_cast<tcp_server_socket*>(sock);
  tcp_sock->stop_threads();
  join();
}


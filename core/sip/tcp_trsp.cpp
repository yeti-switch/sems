#include "tcp_trsp.h"
#include "ip_util.h"
#include "trans_layer.h"

#include "AmUtils.h"

#include <netdb.h>
#include <event2/event.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <AmLcConfig.h>

// avoid sockets in WAITING state. close() will send RST and immediately remove entry from hashtable
#define TCP_STATIC_CLIENT_PORT_CLOSE_NOWAIT 1

int tcp_input::on_input(tcp_base_trsp *socket)
{
    return parse_input(socket);
}

tcp_trsp_socket::tcp_trsp_socket(trsp_server_socket *server_sock, trsp_worker *server_worker, int sd,
                                 const sockaddr_storage *sa, trsp_socket::socket_transport transport,
                                 struct event_base *evbase)
    : tcp_base_trsp(server_sock, server_worker, sd, sa, transport, evbase, new tcp_input)
{
}

tcp_trsp_socket::tcp_trsp_socket(trsp_server_socket *server_sock, trsp_worker *server_worker, int sd,
                                 const sockaddr_storage *sa, trsp_socket::socket_transport transport,
                                 event_base *evbase, trsp_input *input)
    : tcp_base_trsp(server_sock, server_worker, sd, sa, transport, evbase, input)
{
}

tcp_trsp_socket::~tcp_trsp_socket() {}

int tcp_trsp_socket::send(const sockaddr_storage *sa, const string &host, const char *msg, const int msg_len,
                          [[maybe_unused]] unsigned int flags)
{
    std::unique_lock _l(sock_mut);

    if (closed || (check_connection() < 0))
        return -1;

    if (trsp_socket::log_level_raw_msgs >= 0) {
        _LOG(trsp_socket::log_level_raw_msgs, "add msg to send deque/from %s:%i to (%s)%s:%i\n--++--\n%.*s--++--",
             actual_ip.c_str(), actual_port, host.c_str(), get_addr_str(sa).c_str(), am_get_port(sa), msg_len, msg);
    }

    send_q.push_back(new msg_buf(sa, msg, msg_len));

    if (connected) {
        add_write_event();
        DBG3("write event added...");
    }

    return 0;
}

void tcp_trsp_socket::set_connected(bool val)
{
    if (connected != val) {
        tcp_base_trsp::set_connected(val);

        if (connected) {
            tcp_server_socket::tcp_statistics *tcp_stats =
                dynamic_cast<tcp_server_socket::tcp_statistics *>(server_sock->get_statistics());
            if (tcp_stats)
                tcp_stats->incConnectedConnectionsCount(this);
        }
    }
}

tcp_socket_factory::tcp_socket_factory(tcp_base_trsp::socket_transport transport)
    : trsp_socket_factory(transport)
{
}

tcp_base_trsp *tcp_socket_factory::create_socket(trsp_server_socket *server_sock, trsp_worker *server_worker, int sd,
                                                 const sockaddr_storage *sa, const string &, event_base *evbase)
{
    return new tcp_trsp_socket(server_sock, server_worker, sd, sa, transport, evbase);
}

tcp_server_socket::tcp_server_socket(short unsigned int if_num, short unsigned int proto_idx, unsigned int opts,
                                     socket_transport transport)
    : trsp_server_socket(if_num, proto_idx, opts, new tcp_socket_factory(transport),
                         new tcp_statistics(transport, if_num, proto_idx))
{
}

tcp_server_socket::tcp_statistics::tcp_statistics(trsp_socket::socket_transport transport, unsigned short if_num,
                                                  unsigned short proto_idx)
    : trsp_statistics::trsp_st_base(transport, if_num, proto_idx)
    , countOutConnectedConnections(
          stat_group(Gauge, "core", "connections")
              .addAtomicCounter()
              .addLabel("direction", "out")
              .addLabel("state", "connected")
              .addLabel("interface", AmConfig.sip_ifs[if_num].name)
              .addLabel("transport", trsp_socket::socket_transport2proto_str(transport))
              .addLabel("protocol", AmConfig.sip_ifs[if_num].proto_info[proto_idx]->ipTypeToStr()))
    , countInConnectedConnections(
          stat_group(Gauge, "core", "connections")
              .addAtomicCounter()
              .addLabel("direction", "in")
              .addLabel("state", "connected")
              .addLabel("interface", AmConfig.sip_ifs[if_num].name)
              .addLabel("transport", trsp_socket::socket_transport2proto_str(transport))
              .addLabel("protocol", AmConfig.sip_ifs[if_num].proto_info[proto_idx]->ipTypeToStr()))
{
}

void tcp_server_socket::tcp_statistics::changeCountConnection(bool remove, tcp_base_trsp *socket)
{
    trsp_st_base::changeCountConnection(remove, socket);

    if (!socket->is_connected())
        return;

    if (remove)
        decConnectedConnectionsCount(socket);
    else
        incConnectedConnectionsCount(socket);
}

void tcp_server_socket::tcp_statistics::incConnectedConnectionsCount(tcp_base_trsp *socket)
{
    if (socket->is_client())
        countOutConnectedConnections.inc();
    else
        countInConnectedConnections.inc();
}

void tcp_server_socket::tcp_statistics::decConnectedConnectionsCount(tcp_base_trsp *socket)
{
    if (socket->is_client())
        countOutConnectedConnections.dec();
    else
        countInConnectedConnections.dec();
}

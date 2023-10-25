#include <sys/ioctl.h>
#include <algorithm>
#include "tcp_base_trsp.h"
#include "socket_ssl.h"
#include "hash.h"
#include "ip_util.h"
#include "trans_layer.h"
#include "sip_parser.h"
#include "parse_common.h"
#include "parse_via.h"
#include "AmLcConfig.h"
#include "AmUtils.h"

trsp_base_input::trsp_base_input()
: input_len(0)
{
    // async parser state
    pst.reset((char*)input_buf);
}

void trsp_base_input::on_parsed_received_msg(tcp_base_trsp* socket, sip_msg* s_msg)
{
    SIP_info *iface = AmConfig.sip_ifs[socket->server_sock->get_if()].proto_info[socket->server_sock->get_proto_idx()];
    trans_layer::instance()->received_msg((sip_msg*)s_msg,iface->acls);
}

int trsp_base_input::parse_input(tcp_base_trsp* socket)
{
    for(;;) {
        int err = skip_sip_msg_async(&pst, (char*)(input_buf+input_len));
        if(err) {
            if(err == UNEXPECTED_EOT) {
                if(pst.orig_buf > (char*)input_buf) {
                    int addr_shift = pst.orig_buf - (char*)input_buf;
                    memmove(input_buf, pst.orig_buf, input_len - addr_shift);
                    pst.orig_buf = (char*)input_buf;
                    pst.c -= addr_shift;
                    if(pst.beg)
                        pst.beg -= addr_shift;
                    input_len -= addr_shift;
                    return 0;
                } else if(get_input_free_space()){
                    return 0;
                }
                ERROR("message is too big. drop connection. peer %s:%d",
                    socket->get_peer_ip().data(), socket->get_peer_port());
            } else {
                ERROR("parsing error %d. peer %s:%d",
                      err, socket->get_peer_ip().data(), socket->get_peer_port());
            }

            socket->inc_sip_parse_error();

            pst.reset((char*)input_buf);
            reset_input();

            return -1;
        } //if(err)

        int msg_len = pst.get_msg_len();
        if(msg_len > MAX_TCP_MSGLEN) {
            ERROR("message is too big (%d > %d. drop connection. peer %s:%d",
                msg_len, MAX_TCP_MSGLEN,
                socket->get_peer_ip().data(), socket->get_peer_port());
            return -1;
        }

        sip_msg* s_msg = new sip_msg((const char*)pst.orig_buf,msg_len);

        gettimeofday(&s_msg->recv_timestamp,NULL);

        //TODO: use bitmask here as for PI_interface::local_ip_proto2addr_if
        switch(socket->get_transport_id()) {
        case tcp_base_trsp::tls_ipv4:
        case tcp_base_trsp::tls_ipv6:
            s_msg->transport_id = sip_transport::TLS;
            break;
        case tcp_base_trsp::ws_ipv4:
        case tcp_base_trsp::ws_ipv6:
            s_msg->transport_id = sip_transport::WS;
            break;
        case tcp_base_trsp::tcp_ipv4:
        case tcp_base_trsp::tcp_ipv6:
            s_msg->transport_id = sip_transport::TCP;
            break;
        case tcp_base_trsp::wss_ipv4:
        case tcp_base_trsp::wss_ipv6:
            s_msg->transport_id = sip_transport::WSS;
            break;
        default:
            ERROR("unexpected socket transport_id: %d. set TCP as fallback", socket->get_transport_id());
            s_msg->transport_id = sip_transport::TCP;
        }

        socket->copy_peer_addr(&s_msg->remote_ip);
        socket->copy_addr_to(&s_msg->local_ip);

        char host[NI_MAXHOST] = "";
        DBG("vv M [|] u recvd msg via %s/%i from %s:%i to %s:%i. bytes: %d vv"
            "--++--\n%.*s--++--\n",
            socket->get_transport(),
            socket->sd,
            am_inet_ntop_sip(&s_msg->remote_ip,host,NI_MAXHOST),
            am_get_port(&s_msg->remote_ip),
            am_inet_ntop_sip(&s_msg->local_ip,host,NI_MAXHOST),
            am_get_port(&s_msg->local_ip),
            s_msg->len,
            s_msg->len, s_msg->buf);

        s_msg->local_socket = socket;
        inc_ref(socket);

        // pass message to the parser / transaction layer
        on_parsed_received_msg(socket, s_msg);

        char* msg_end = pst.orig_buf + msg_len;
        char* input_end = (char*)input_buf + input_len;

        if(msg_end < input_end) {
            pst.reset(msg_end);
        } else {
            pst.reset((char*)input_buf);
            reset_input();
            return 0;
        }
    } //for(;;)

    // fake:
    //return 0;
}

void tcp_base_trsp::on_sock_read([[maybe_unused]] int fd, short ev, void* arg)
{
    if(ev & (EV_READ|EV_TIMEOUT)) {
        ((tcp_base_trsp*)arg)->on_read(ev);
    }
}

void tcp_base_trsp::on_sock_write([[maybe_unused]] int fd, short ev, void* arg)
{
    if(ev & (EV_WRITE|EV_TIMEOUT)) {
        ((tcp_base_trsp*)arg)->on_write(ev);
    }
}

tcp_base_trsp::tcp_base_trsp(
    trsp_server_socket* server_sock_, trsp_worker* server_worker_,
    int sd, const sockaddr_storage* sa, trsp_socket::socket_transport transport,
    event_base* evbase_, trsp_input* input_)
  : trsp_socket(
        server_sock_->get_sip_parse_errors(),
        server_sock_->get_if(),
        server_sock_->get_proto_idx(),0,transport,0,sd),
    server_sock(server_sock_), server_worker(server_worker_),
    input(input_), closed(false),
    connected(false), evbase(evbase_),
    read_ev(NULL), write_ev(NULL)
{
    sockaddr_ssl* sa_ssl = (sockaddr_ssl*)(sa);
    CLASS_DBG("tcp_base_trsp() server_socket:%p transport:%d sa:%s:%i trsp:%d ssl_marker:%d sig:%d cipher:%d mac:%d",
              server_sock, transport,
              am_inet_ntop(sa).c_str(), am_get_port(sa),
              sa_ssl->trsp,
              sa_ssl->ssl_marker,
              sa_ssl->sig,
              sa_ssl->cipher,
              sa_ssl->mac);

    // local address
    actual_ip = ip = server_sock->get_ip();
    actual_port = port = server_sock->get_port();
    socket_options = server_sock->get_options();
    server_sock->copy_addr_to(&addr);

    // peer address
    memcpy(&peer_addr,sa,sizeof(sockaddr_storage));

    char host[NI_MAXHOST] = "";
    peer_ip = am_inet_ntop(&peer_addr,host,NI_MAXHOST);
    peer_port = am_get_port(&peer_addr);

    if(sd > 0) {
        create_events();
    }
}

tcp_base_trsp::~tcp_base_trsp()
{
    CLASS_DBG("~tcp_base_trsp()");
    if(read_ev) {
        DBG("%p destroy read_ev %p",this, read_ev);
        event_del(read_ev);
        event_free(read_ev);
    }

    if(write_ev) {
        DBG("%p destroy write_ev %p",this, write_ev);
        event_del(write_ev);
        event_free(write_ev);
    }

    if(sd > 0) {
        ::close(sd);
        sd = -1;
    }

    delete input;
}

void tcp_base_trsp::close()
{
    atomic_ref_guard _ref_guard(this);

    server_worker->remove_connection(this);

    closed = true;
    DBG("********* closing connection ***********");
    DBG("connection type %s", get_transport());

    if(read_ev) {
        DBG("%p destroy read_ev %p", this, read_ev);
        event_del(read_ev);
        event_free(read_ev);
        read_ev = NULL;
    }

    if(write_ev) {
        DBG("%p destroy write_ev %p", this, write_ev);
        event_del(write_ev);
        event_free(write_ev);
        write_ev = NULL;
    }

    if(sd > 0) {
        ::close(sd);
        sd = -1;
    }

    generate_transport_errors();
}

void tcp_base_trsp::generate_transport_errors()
{

    /* avoid deadlock between session processor and tcp worker.
       it is safe to unlock here because 'closed' flag is set to true and
       send_q will not be affected by send() anymore.
       do not forget to avoid double mutex unlock in places where close() is called
    */
    sock_mut.unlock();

    while(!send_q.empty()) {

        msg_buf* msg = send_q.front();
        send_q.pop_front();

        sip_msg s_msg(msg->msg,msg->msg_len);
        delete msg;

        copy_peer_addr(&s_msg.remote_ip);
        copy_addr_to(&s_msg.local_ip);

        trans_layer::instance()->transport_error(&s_msg);
    }
}

void tcp_base_trsp::add_read_event_ul()
{
    sock_mut.unlock();
    add_read_event();
    sock_mut.lock();
}

void tcp_base_trsp::add_read_event()
{
    DBG("%p add read_ev %p",this, read_ev);
    event_add(read_ev, server_sock->get_idle_timeout());
}

void tcp_base_trsp::add_write_event_ul(struct timeval* timeout)
{
    sock_mut.unlock();
    add_write_event(timeout);
    sock_mut.lock();
}

void tcp_base_trsp::add_write_event(struct timeval* timeout)
{
    DBG("%p add write_ev %p",this, write_ev);
    event_add(write_ev, timeout);
}

void tcp_base_trsp::create_events()
{
    if(read_ev) {
        ERROR("read event already created: transport %s, ip %s, port %d", get_transport(), am_inet_ntop(&peer_addr).c_str(), am_get_port(&peer_addr));
    }
    read_ev = event_new(evbase, sd, EV_READ|EV_PERSIST,
                        tcp_base_trsp::on_sock_read,
                        (void *)this);
    DBG("%p created read_ev %p with base %p",this, read_ev, evbase);

    if(write_ev) {
        ERROR("write event already created: transport %s, ip %s, port %d", get_transport(), am_inet_ntop(&peer_addr).c_str(), am_get_port(&peer_addr));
    }
    write_ev = event_new(evbase, sd, EV_WRITE,
                         tcp_base_trsp::on_sock_write,
                         (void *)this);
    DBG("%p created write_ev %p with base %p",this, write_ev, evbase);
}

int tcp_base_trsp::connect()
{
    int true_opt = 1;

    sockaddr_ssl* peer_addr_ssl = reinterpret_cast<sockaddr_ssl*>(&peer_addr);

    CLASS_DBG("tcp_base_trsp::connect(): sd:%d ss_family:%d addr:%s:%i trsp:%d ssl_marker:%d sig:%d cipher:%d mac:%d", sd,
        peer_addr.ss_family,
        am_inet_ntop(&peer_addr).c_str(), am_get_port(&peer_addr),
        peer_addr_ssl->trsp,
        peer_addr_ssl->ssl_marker,
        peer_addr_ssl->sig,
        peer_addr_ssl->cipher,
        peer_addr_ssl->mac);

    if(sd > 0) {
        ERROR("pending connection request: close first.");
        return -1;
    }

    if((sd = socket(peer_addr.ss_family,SOCK_STREAM,0)) == -1){
        ERROR("socket: %s",strerror(errno));
        return -1;
    }
    SOCKET_LOG("socket(peer_addr.ss_family(%d),SOCK_STREAM,0) = %d", peer_addr.ss_family, sd);

    if(ioctl(sd, FIONBIO , &true_opt) == -1) {
        ERROR("could not make new connection non-blocking: %s",strerror(errno));
        ::close(sd);
        sd = -1;
        return -1;
    }

    if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR,
       (void*)&true_opt, sizeof (true_opt)) == -1)
    {
        ERROR("setsockopt(SO_REUSEADDR): %s",strerror(errno));
        ::close(sd);
        return -1;
    }

    if(socket_options & static_client_port) {
        if(setsockopt(sd, SOL_SOCKET, SO_REUSEPORT,
           (void*)&true_opt, sizeof (true_opt)) == -1)
        {
            ERROR("setsockopt(SO_REUSEPORT): %s",strerror(errno));
            ::close(sd);
            return -1;
        }
#if TCP_STATIC_CLIENT_PORT_CLOSE_NOWAIT==1
        struct linger linger_opt = {
            .l_onoff = 1,
            .l_linger = 0
        };
        if(setsockopt(sd, SOL_SOCKET, SO_LINGER,
           (void*)&linger_opt, sizeof (struct linger)) == -1)
        {
            ERROR("setsockopt(SO_LINGER): %s",strerror(errno));
            return -1;
        }
#endif
    } else {
        am_set_port(&addr,0);
    }

    if(::bind(sd,(const struct sockaddr*)&addr,SA_len(&addr)) < 0) {
        CLASS_ERROR("bind: %s",strerror(errno));
        ::close(sd);
        return -1;
    }

    DBG("connecting to %s:%i...",
        am_inet_ntop(&peer_addr).c_str(),
        am_get_port(&peer_addr));

    return ::connect(sd, (const struct sockaddr*)&peer_addr, SA_len(&peer_addr));
}

int tcp_base_trsp::check_connection()
{
    if(sd < 0) {
        int ret = connect();
        if(ret < 0) {
            if(errno != EINPROGRESS && errno != EALREADY) {
                ERROR("could not connect to %s:%d: %s",
                    am_inet_ntop(&peer_addr).c_str(),
                    am_get_port(&peer_addr),
                    strerror(errno));
                ::close(sd);
                sd = -1;
                return -1;
            }
        }

        //memorize actual ip/port
        sockaddr_storage actual_addr;
        socklen_t actual_addr_len = sizeof(actual_addr);
        getsockname(sd,(sockaddr *)&actual_addr,&actual_addr_len);
        actual_ip = am_inet_ntop(&actual_addr);
        actual_port = am_get_port(&actual_addr);

        // it's time to create the events...
        create_events();

        if(ret < 0) {
            add_write_event(server_sock->get_connect_timeout());
            DBG("connect event added...");

            // because of unlock in ad_write_event_ul,
            // on_connect() might already have been scheduled
            if(closed)
                return -1;
        } else {
            // connect succeeded immediatly
            connected = true;
            add_read_event();
        }
    } //if(sd < 0)

    return 0;
}

void tcp_base_trsp::on_read(short ev)
{
    assert(input);

    int bytes = 0;
    {   // locked section

        AmControlledLock _l(sock_mut);

        if(ev & EV_TIMEOUT) {
            DBG("************ idle timeout: closing connection **********");
            close();
            _l.release_ownership();
            return;
        }

        DBG("on_read (connected = %i, transport = %s)",connected, get_transport());

        bytes = ::read(sd,input->get_input(),input->get_input_free_space());
        if(bytes < 0) {
            switch(errno) {
            case EAGAIN:
                return; // nothing to read

            case ECONNRESET:
            case ENOTCONN:
                DBG("connection has been closed (sd=%i)",sd);
                close();
                _l.release_ownership();
                return;

            case ETIMEDOUT:
                DBG("transmission timeout (sd=%i)",sd);
                close();
                _l.release_ownership();
                return;

            default:
                DBG("unknown error (%i): %s",errno,strerror(errno));
                close();
                _l.release_ownership();
                return;
            }
        } else if(bytes == 0) {
            // connection closed
            DBG("connection has been closed (sd=%i)",sd);
            close();
            _l.release_ownership();
            return;
        }
    } // end of - locked section

    input->add_input_len(bytes);

    // ... and parse it
    if(input->on_input(this) < 0) {
        DBG("Error while parsing input: closing connection!");
        sock_mut.lock();
        close();
        //sock_mut.unlock();
    }
}

void tcp_base_trsp::getInfo(AmArg &ret)
{
    AmLock l(sock_mut);

    ret["sd"] = sd;
    ret["actual_address"] = get_actual_ip();
    ret["actual_port"] = get_actual_port();
    ret["proto"] = get_transport();
    ret["ifnum"] = if_num;
    ret["queue_size"] = send_q.size();
}

void tcp_base_trsp::on_write(short ev)
{
    atomic_ref_guard _ref_guard(this);
    AmControlledLock _l(sock_mut);

    DBG("on_write (connected = %i, transport = %s)",connected, get_transport());
    if(!connected) {
        if(on_connect(ev) != 0) {
            _l.release_ownership();
            return;
        }
    }

    pre_write();
    while(!send_q.empty() && !closed) {

        msg_buf* msg = send_q.front();
        if(!msg || !msg->bytes_left()) {
            send_q.pop_front();
            delete msg;
            continue;
        }

        // send msg
        int bytes = write(sd,msg->cursor,msg->bytes_left());
        if(bytes < 0) {
            DBG("error on write: %i",bytes);
            switch(errno) {
            case EINTR:
            case EAGAIN: // would block
                add_write_event();
                break;

            default: // unforseen error: close connection
                ERROR("unforseen error: close connection (%i/%s)",
                      errno,strerror(errno));
                close();
                _l.release_ownership();
                break;
            }
            return;
        }

        DBG("sent msg via %s/%i from %s:%i to %s:%i. bytes: %d/%d",
            get_transport(),
            sd,
            actual_ip.c_str(), actual_port,
            get_addr_str(&msg->addr).c_str(),
            am_get_port(&msg->addr),
            bytes,
            msg->bytes_left());

        if(bytes < msg->bytes_left()) {
            msg->cursor += bytes;
            add_write_event();
            return;
        }

        send_q.pop_front();
        delete msg;
    } //while(!send_q.empty())

    if(!closed) post_write();
}

int tcp_base_trsp::on_connect(short ev)
{
    DBG("************ on_connect() ***********");
    DBG("connection type %s", get_transport());

    if(ev & EV_TIMEOUT) {
        DBG("********** connection timeout on sd=%i ************",sd);
        close();
        return -1;
    }

    socklen_t len = sizeof(int);
    int error = 0;
    if(getsockopt(sd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        ERROR("getsockopt: %s",strerror(errno));
        close();
        return -1;
    }

    if(error != 0) {
        DBG("*********** connection error (sd=%i): %s *********",
            sd,strerror(error));
        close();
        return -1;
    }

    DBG("TCP connection from %s:%u",
        get_peer_ip().c_str(),
        get_peer_port());
    connected = true;
    add_read_event();

    return 0;
}

tcp_base_trsp::msg_buf::msg_buf(
    const sockaddr_storage* sa, const char* msg,
    const int msg_len)
  : msg_len(msg_len)
{
    memcpy(&addr,sa,sizeof(sockaddr_storage));
    cursor = this->msg = new char[msg_len];
    memcpy(this->msg,msg,msg_len);
}

tcp_base_trsp::msg_buf::~msg_buf()
{
    delete [] msg;
}

void tcp_base_trsp::copy_peer_addr(sockaddr_storage* sa)
{
    memcpy(sa,&peer_addr,sizeof(sockaddr_storage));
}

tcp_base_trsp* trsp_socket_factory::new_connection(
    trsp_server_socket* server_sock,
    trsp_worker* server_worker,
    int sd, const sockaddr_storage* sa,
    struct event_base* evbase)
{
    return create_socket(server_sock, server_worker,sd,sa,evbase);
}

trsp_worker::trsp_worker()
{
    evbase = event_base_new();
}

trsp_worker::~trsp_worker()
{
    event_base_free(evbase);
    connections_mut.lock();
    for(auto conn_m : connections) {
        dec_ref(conn_m.second);
    }
    connections_mut.unlock();
}

void trsp_worker::add_connection(tcp_base_trsp* client_sock)
{
    string conn_id = client_sock->get_peer_ip()
                     + ":" + int2str(client_sock->get_peer_port());

    DBG("new TCP connection from %s:%u",
        client_sock->get_peer_ip().c_str(),
        client_sock->get_peer_port());

    connections_mut.lock();
    auto sock_it = connections.find(conn_id);
    if(sock_it != connections.end()) {
        sockaddr_storage sa = {0, {0}, 0};
        client_sock->copy_peer_addr(&sa);
    }

    connections[conn_id] = client_sock;

    inc_ref(client_sock);
    connections_mut.unlock();
}

void trsp_worker::remove_connection(tcp_base_trsp* client_sock)
{
    string conn_id = 
        client_sock->get_peer_ip() + ":" + int2str(client_sock->get_peer_port());

    DBG("removing TCP connection from %s",conn_id.c_str());

    connections_mut.lock();
    auto sock_it = connections.find(conn_id);
    if(sock_it != connections.end()) {
        sockaddr_storage sa = {0, {0}, 0};
        client_sock->copy_peer_addr(&sa);
        dec_ref(sock_it->second);

        DBG("TCP connection from %s removed",conn_id.c_str());

        connections.erase(sock_it);
    }
    connections_mut.unlock();
}

int trsp_worker::send(
    trsp_server_socket* server_sock, const sockaddr_storage* sa, const char* msg,
    const int msg_len, unsigned int flags)
{
    char host_buf[NI_MAXHOST];
    string dest = am_inet_ntop(sa,host_buf,NI_MAXHOST);
    dest += ":" + int2str(am_get_port(sa));
    tcp_base_trsp* sock = NULL;


    bool new_conn=false;
    connections_mut.lock();
    auto sock_it = connections.find(dest);
    if(sock_it != connections.end()) {
        sock = sock_it->second;
        inc_ref(sock);
        sockaddr_ssl* sa_ssl = (sockaddr_ssl*)sa;
        sockaddr_storage peer_addr;
        sock->copy_peer_addr(&peer_addr);
        sockaddr_ssl* peer_ssl = (sockaddr_ssl*)&peer_addr;
        if(sa_ssl->ssl_marker^peer_ssl->ssl_marker)
            WARN("send/peer addresses ssl markers are not equal: send %d, peer %d",
                 sa_ssl->ssl_marker, peer_ssl->ssl_marker);
    }

    if(!sock) {
        //TODO: add flags to avoid new connections (ex: UAs behind NAT)
        tcp_base_trsp* new_sock = new_connection(server_sock, sa);
        if(new_sock) {
            sock = new_sock;
            inc_ref(sock);
            new_conn = true;
        }
    }
    connections_mut.unlock();

    if(!sock) return -1;

    // must be done outside from connections_mut
    // to avoid dead-lock with the event base
    int ret = sock->send(sa,msg,msg_len,flags);
    if((ret < 0) && new_conn) {
        remove_connection(sock);
    }
    dec_ref(sock);

    return ret;
}

void trsp_worker::create_connected(trsp_server_socket* server_sock, int sd, const sockaddr_storage* sa)
{
    if(sd < 0) {
        return;
    }
    tcp_base_trsp* new_sock = server_sock->sock_factory->new_connection(server_sock,this,sd,sa,evbase);
    if(new_sock) {
        add_connection(new_sock);
        new_sock->connected = true;
        new_sock->add_read_event();
    } else {
        close(sd);
    }
}


tcp_base_trsp* trsp_worker::new_connection(trsp_server_socket* server_sock, const sockaddr_storage* sa)
{
    char host_buf[NI_MAXHOST];
    string dest = am_inet_ntop(sa,host_buf,NI_MAXHOST);
    dest += ":" + int2str(am_get_port(sa));
    tcp_base_trsp* new_sock = server_sock->sock_factory->new_connection(server_sock,this,-1,sa,evbase);
    if(!new_sock) return 0;
    connections[dest] = new_sock;
    inc_ref(new_sock);
    return new_sock;
}

void trsp_worker::getInfo(AmArg &ret)
{
    AmLock l(connections_mut);

    ret.assertStruct();
    for(auto const &con_it: connections) {
        SIP_interface &sip_if = AmConfig.sip_ifs[con_it.second->get_if()];
        AmArg &r = ret[sip_if.name];
        con_it.second->getInfo(r[con_it.first]);
    }
}

void trsp_worker::run()
{
    // fake event to prevent the event loop from exiting
    int fake_fds[2];
    int ret = pipe(fake_fds);
    (void)ret;
    struct event* ev_default =
        event_new(evbase,fake_fds[0],
                  EV_READ|EV_PERSIST,
                  NULL,NULL);
    event_add(ev_default,NULL);

    setThreadName("sip-worker");

    /* Start the event loop. */
    /*int ret = */event_base_dispatch(evbase);

    // clean-up fake fds/event
    event_free(ev_default);
    close(fake_fds[0]);
    close(fake_fds[1]);
    stopped.set(true);
}

void trsp_worker::on_stop()
{
    event_base_loopbreak(evbase);
    stopped.wait_for();
}

trsp_server_socket::trsp_server_socket(
    unsigned short if_num, unsigned short proto_idx, unsigned int opts, trsp_socket_factory* sock_factory)
  : trsp_socket(
        stat_group(Counter, "core", "sip_parse_errors").addAtomicCounter()
            .addLabel("interface", AmConfig.sip_ifs[if_num].name)
            .addLabel("transport", socket_transport2proto_str(sock_factory->transport))
            .addLabel("protocol", AmConfig.sip_ifs[if_num].proto_info[proto_idx]->ipTypeToStr()),
        if_num, proto_idx, opts, sock_factory->transport),
    ev_accept(nullptr),
    sock_factory(sock_factory)
{
    inc_ref(sock_factory);
}

trsp_server_socket::~trsp_server_socket()
{
    dec_ref(sock_factory);
    if(ev_accept) {
        event_free(ev_accept);
    }
}

int trsp_server_socket::bind(const string& bind_ip, unsigned short bind_port)
{
    if(sd) {
        WARN("re-binding socket");
        close(sd);
    }

    if(am_inet_pton(bind_ip.c_str(),&addr) == 0) {

        ERROR("am_inet_pton(%s): %s",bind_ip.c_str(),strerror(errno));
        return -1;
    }

    if( ((addr.ss_family == AF_INET) &&
            (SAv4(&addr)->sin_addr.s_addr == INADDR_ANY)) ||
            ((addr.ss_family == AF_INET6) &&
             IN6_IS_ADDR_UNSPECIFIED(&SAv6(&addr)->sin6_addr)) ) {

        ERROR("Sorry, we cannot bind to 'ANY' address");
        return -1;
    }

    am_set_port(&addr,bind_port);

    if((sd = socket(addr.ss_family,SOCK_STREAM,0)) == -1) {
        ERROR("socket: %s",strerror(errno));
        return -1;
    }
    SOCKET_LOG("socket(addr.ss_family(%d),SOCK_STREAM,0) = %d", addr.ss_family, sd);

    int true_opt = 1;
    if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR,
                  (void*)&true_opt, sizeof (true_opt)) == -1) {
        ERROR("%s",strerror(errno));
        close(sd);
        return -1;
    }

    if(socket_options & static_client_port) {
        if(setsockopt(sd, SOL_SOCKET, SO_REUSEPORT,
                      (void*)&true_opt, sizeof (true_opt)) == -1) {
            ERROR("%s",strerror(errno));
            close(sd);
            return -1;
        }
    }

    if(ioctl(sd, FIONBIO , &true_opt) == -1) {
        ERROR("setting non-blocking: %s",strerror(errno));
        close(sd);
        return -1;
    }

    if(::bind(sd,(const struct sockaddr*)&addr,SA_len(&addr)) < 0) {

        ERROR("bind: %s",strerror(errno));
        close(sd);
        return -1;
    }

    if(::listen(sd, 16) < 0) {
        ERROR("listen: %s",strerror(errno));
        close(sd);
        return -1;
    }

    actual_port = port = bind_port;
    actual_ip = ip   = bind_ip;

    DBG("TCP transport bound to %s/%i",ip.c_str(),port);

    return 0;
}

void trsp_server_socket::on_accept(int fd, short ev, void* arg)
{
    trsp_server_socket* trsp = (trsp_server_socket*)arg;
    trsp->on_accept(fd,ev);
}

uint32_t trsp_server_socket::hash_addr(const sockaddr_storage* addr)
{
    unsigned int port = am_get_port(addr);
    uint32_t h=0;
    if(addr->ss_family == AF_INET) {
        h = hashlittle(&SAv4(addr)->sin_addr,sizeof(in_addr),port);
    }
    else {
        h = hashlittle(&SAv6(addr)->sin6_addr,sizeof(in6_addr),port);
    }
    return h;
}

void trsp_server_socket::add_event(struct event_base *evbase)
{
    this->evbase = evbase;

    if(!ev_accept) {
        ev_accept = event_new(evbase, sd, EV_READ|EV_PERSIST,
                              trsp_server_socket::on_accept, (void *)this);
        DBG("%p created ev_accept %p with base %p",this, ev_accept, evbase);
        DBG("%p add ev_accept %p",this, ev_accept);
        event_add(ev_accept, NULL); // no timeout
    }
}

void trsp_server_socket::add_workers(trsp_worker **trsp_workers, unsigned short n_trsp_workers)
{
    for(unsigned int i=0; i<n_trsp_workers; i++) {
        workers.push_back(trsp_workers[i]);
    }
}

void trsp_server_socket::on_accept(int sd, [[maybe_unused]] short ev)
{
    sockaddr_storage src_addr = {0, {0}, 0};
    socklen_t        src_addr_len = sizeof(sockaddr_storage);

    int connection_sd = accept(sd,(sockaddr*)&src_addr,&src_addr_len);
    SOCKET_LOG("accept(sd,...) = %d", connection_sd);
    if(connection_sd < 0) {
        WARN("error while accepting connection");
        return;
    }

    int true_opt = 1;
    if(ioctl(connection_sd, FIONBIO , &true_opt) == -1) {
        ERROR("could not make new connection non-blocking: %s",strerror(errno));
        close(connection_sd);
        return;
    }

    uint32_t h = hash_addr(&src_addr);
    unsigned int idx = h % workers.size();

    // in case of thread pooling, do following in worker thread
    DBG("trsp_server_socket::create_connected (idx = %u)",idx);
    workers[idx]->create_connected(this, connection_sd,&src_addr);
}

int trsp_server_socket::send(const sockaddr_storage* sa, const char* msg,
                             const int msg_len, unsigned int flags)
{
    uint32_t h = hash_addr(sa);
    unsigned int idx = h % workers.size();
    DBG("trsp_server_socket::send: idx = %u",idx);
    return workers[idx]->send(this, sa,msg,msg_len,flags);
}

void trsp_server_socket::set_connect_timeout(unsigned int ms)
{
    connect_timeout.tv_sec = ms / 1000;
    connect_timeout.tv_usec = (ms % 1000) * 1000;
}

void trsp_server_socket::set_idle_timeout(unsigned int ms)
{
    idle_timeout.tv_sec = ms / 1000;
    idle_timeout.tv_usec = (ms % 1000) * 1000;
}

struct timeval* trsp_server_socket::get_connect_timeout()
{
    if(connect_timeout.tv_sec || connect_timeout.tv_usec)
        return &connect_timeout;

    return NULL;
}

struct timeval* trsp_server_socket::get_idle_timeout()
{
    if(idle_timeout.tv_sec || idle_timeout.tv_usec)
        return &idle_timeout;

    return NULL;
}

trsp::trsp()
{
    evbase = event_base_new();
}

trsp::~trsp()
{
  if(evbase) {
    event_base_free(evbase);
  }
}

void trsp::add_socket(trsp_server_socket* sock)
{
    sock->add_event(evbase);
    INFO("Added SIP server %s transport on %s:%i",
        sock->get_transport(), sock->get_ip(),sock->get_port());
}

/** @see AmThread */
void trsp::run()
{
    INFO("Started SIP server thread");
    setThreadName("sip-server-trsp");

    /* Start the event loop. */
    event_base_dispatch(evbase);

    INFO("SIP server thread finished");
}

/** @see AmThread */
void trsp::on_stop()
{
    event_base_loopbreak(evbase);
    join();
}

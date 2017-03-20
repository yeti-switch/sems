#include "SctpClientConnection.h"

#include "sip/ip_util.h"

#include <sys/epoll.h>
#include <netdb.h>
#include <netinet/sctp.h>

#include "jsonArg.h"
#include "AmUtils.h"

#include "SctpBusEventRequest.pb.h"
#include "AmConfig.h"

#include "AmSessionContainer.h"

int SctpClientConnection::init(int efd, const sockaddr_storage &a,int reconnect_seconds)
{
    set_addr(a);
    set_epoll_fd(efd);
    reconnect_interval = reconnect_seconds;
    timerclear(&last_connect_attempt);

    if(-1 == connect())
        return -1;

    return 0;
}

int SctpClientConnection::connect()
{
    DBG("connect to %s:%d",am_inet_ntop(&addr).c_str(),am_get_port(&addr));

    close();
    events_sent = 0;

    if((fd = socket(addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_SCTP )) == -1)
        sctp_sys_err("socket()");

    state = Connected;

    int opt = 1;
    if( ::setsockopt(fd, IPPROTO_SCTP, SCTP_NODELAY, (char *)&opt, sizeof(int)) < 0 )
        sctp_sys_err("setsockopt(IPPROTO_SCTP, SCTP_NODELAY)");

    struct sctp_event_subscribe event;
    event.sctp_association_event = 1;
    event.sctp_shutdown_event = 1;

    if(::setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS, &event, sizeof(event)) < 0)
        sctp_sys_err("setsockopt(SCTP_EVENTS)");

    gettimeofday(&last_connect_attempt,NULL);

    if(::connect(fd, reinterpret_cast<sockaddr *>(&addr), SA_len(&addr)) == -1) {
        if(errno == EINPROGRESS)
            state = Connecting;
        else
            return -1;
    }

    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR,
        .data = {
            .fd = fd
        }
    };

    if(state != Connected)
        ev.events |= EPOLLOUT;

    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1)
        sctp_sys_err("epoll_ctl(EPOLL_CTL_ADD)");

    return 0;
}

void SctpClientConnection::process(uint32_t events) {

    if(events & ~(EPOLLIN | EPOLLOUT)) {
        int err = 0;
        socklen_t len = sizeof(err);

        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);

        ERROR("%s:%u (%d) connection error: %s",
            am_inet_ntop(&addr).c_str(), am_get_port(&addr),fd,
            err ? strerror(err) : "Peer shutdown");

        //state = Closed;
        close();

        return;
    }

    if(events & EPOLLIN) {
        recv();
    }

    if(events & EPOLLOUT) {
        state = Connected;
        INFO("connected to %s:%u/%d (%d) ",
             am_inet_ntop(&addr).c_str(),
             am_get_port(&addr),
             assoc_id, fd);
        struct epoll_event ev = {
            .events = EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR,
            .data = {
                .fd = fd
            }
        };
        if(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) == -1)
            close();
    }
}

void SctpClientConnection::recv()
{
    struct sctp_sndrcvinfo  sinfo;
    int                     flags = 0;
    struct sockaddr_storage from;
    socklen_t               fromlen = sizeof (struct sockaddr_in6);

    ssize_t nread = sctp_recvmsg(
        fd, payload, sizeof(payload)-1,
        (struct sockaddr *)&from,
        &fromlen,
        &sinfo, &flags);

    if(nread < 1) {
        ERROR("sctp_recvmsg(): %m");
        return;
    }

    if( flags & MSG_NOTIFICATION ) {
        handle_notification(from);
        return;
    }

    if(!(flags & MSG_EOR)) {
        ERROR("Truncated message received");
        return;
    }

    DBG("got data in client connection. ignore it");
}

void SctpClientConnection::handle_notification(const sockaddr_storage &from)
{
    const auto sn = (sctp_notification *)payload;
    switch(sn->sn_header.sn_type) {
    case SCTP_ASSOC_CHANGE: {
        const auto &sac = sn->sn_assoc_change;
        assoc_id = sac.sac_assoc_id;
        INFO("SCTP_ASSOC_CHANGE: %d. remote: %s:%u",
             assoc_id,
             am_inet_ntop(&addr).c_str(), am_get_port(&addr));
    } break;
    default:;
    }
}

void SctpClientConnection::send(const SctpBusSendEvent &e)
{
    if(state!=Connected) {
        ERROR("attempt to send event to not connected peer %d",_id);
        return;
    }

    SctpBusEventRequest r;

    if(!AmConfig::node_id) {
        WARN("node_id is 0 (default value). this may cause not intended behavior");
    }

    r.set_src_node_id(AmConfig::node_id);
    r.set_src_session_id(e.src_session_id);
    r.set_dst_node_id(_id);
    r.set_dst_session_id(e.dst_session_id);

    //!TODO: implement direct serialization AmArg -> protobuf
    r.set_json_data(arg2json(e.data));

    if(!r.SerializePartialToArray(payload,sizeof(payload))){
        ERROR("event serialization failed");
        return;
    }

    ssize_t size = r.ByteSize();

    DBG("SEND sctp_bus event %d:%s/%d -> %d:%s",
        r.src_node_id(),
        r.src_session_id().c_str(),
        assoc_id,
        r.dst_node_id(),
        r.dst_session_id().c_str());

    if(::send(fd, payload, size, SCTP_UNORDERED | MSG_NOSIGNAL) != size) {
       ERROR("send(): %m");
    }
    events_sent++;
}

void SctpClientConnection::on_timer()
{
    /*DBG("client on timer. state = %d, last connect: %s",
        state,timeval2str_ntp(last_connect_attempt).c_str());*/
    if(state!=Connected && timerisset(&last_connect_attempt)) {
        timeval now, delta;
        gettimeofday(&now,NULL);
        timersub(&now,&last_connect_attempt,&delta);
        if(delta.tv_sec > reconnect_interval) {
            DBG("reconnect timeout for not connected %s:%d",
                am_inet_ntop(&addr).c_str(),am_get_port(&addr));
            connect();
        }
    }

    /*if(state==Connected) {
        AmSessionContainer::instance()->postEvent(
            SCTP_BUS_EVENT_QUEUE,
            new SctpBusSendEvent("fake_src_id","1-some_dst_id",AmArg("test")));
    }*/
}

void SctpClientConnection::getInfo(AmArg &info)
{
    static const char *status_str[] = {"Closed","Connecting","Connected"};

    info["assoc_id"] = (unsigned long)assoc_id;
    info["events_sent"] = events_sent;
    info["remote_host"] = am_inet_ntop(&addr);
    info["remote_port"] = am_get_port(&addr);
    info["state"] = status_str[state];
}

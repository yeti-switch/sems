#include "SctpClientConnection.h"

#include "sip/ip_util.h"

#include <sys/epoll.h>
#include <netdb.h>
#include <netinet/sctp.h>

#include "jsonArg.h"
#include "AmUtils.h"

#include "SctpBusPDU.pb.h"

#include "AmSessionContainer.h"
#include "AmEventDispatcher.h"

int SctpClientConnection::init(int efd, const sockaddr_storage &a,int reconnect_seconds,
                               const string &sink)
{
    set_addr(a);
    set_epoll_fd(efd);
    reconnect_interval = reconnect_seconds;
    timerclear(&last_connect_attempt);
    event_sink = sink;

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
    bzero(&event, sizeof(struct sctp_event_subscribe));
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

    return fd;
}

int SctpClientConnection::process(uint32_t events) {

    if(events & ~(EPOLLIN | EPOLLOUT)) {
        int err = 0;
        socklen_t len = sizeof(err);

        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);

        ERROR("%s:%u (%d,%d) connection error: %s",
            am_inet_ntop(&addr).c_str(), am_get_port(&addr),fd,events,
            err ? strerror(err) : "Peer shutdown");

        //state = Closed;
        return close();
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
        if(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) == -1) {
            DBG("epoll_ctl(%d,EPOLL_CTL_MOD,%d,EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR): %m",
                epoll_fd,fd);
            return close();
        }

        if(!event_sink.empty()) {
            AmSessionContainer::instance()->postEvent(
                event_sink,
                new SctpBusConnectionStatus(_id, SctpBusConnectionStatus::Connected));
        }

    }

    if(events & EPOLLIN) {
        return recv();
    }

    return 0;
}

int SctpClientConnection::recv()
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
        ERROR("sctp_recvmsg(fd=%d): %m",fd);
        return close();
    }

    if( flags & MSG_NOTIFICATION ) {
        handle_notification(from);
        return 0;
    }

    if(!(flags & MSG_EOR)) {
        ERROR("Truncated message received");
        return 0;
    }

    SctpBusPDU r;
    if(!r.ParseFromArray(payload,nread)){
        ERROR("failed to deserialize PDU from: %s,with len: %ld",
              am_inet_ntop(&from).c_str(),
              nread);
        return 0;
    }
    onIncomingPDU(r);

    return 0;
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

    SctpBusPDU r;

    if(!AmConfig.node_id) {
        WARN("node_id is 0 (default value). this may cause not intended behavior");
    }

    r.set_src_node_id(AmConfig.node_id);
    r.set_src_session_id(e.src_session_id);
    r.set_dst_node_id(_id);
    r.set_dst_session_id(e.dst_session_id);

    //!TODO: implement direct serialization AmArg -> protobuf
    r.set_payload(arg2json(e.data));
    //r.set_json_data(arg2json(e.data));

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

void SctpClientConnection::send(const SctpBusRawRequest &e)
{
    if(state!=Connected) {
        ERROR("attempt to send event to not connected peer %d",_id);
        //FIXME: maybe wait for connect/reconnect here or send reply event with error
        if(e.reply_timeout) {
            AmSessionContainer::instance()->postEvent(
                e.src_session_id,
                new SctpBusRawReply(e,SctpBusRawReply::RES_NOT_CONNECTED));
        }
        return;
    }

    SctpBusPDU r;

    r.set_src_node_id(AmConfig.node_id);
    r.set_src_session_id(e.src_session_id);
    r.set_dst_node_id(e.dst_id);
    r.set_dst_session_id(e.dst_session_id);

    last_cseq++;
    r.set_sequence(last_cseq);
    sent_requests.emplace(last_cseq, e);

    r.set_payload(e.data.data(),e.data.size());

    if(!r.SerializePartialToArray(payload,sizeof(payload))){
        ERROR("event serialization failed");
        return;
    }

    ssize_t size = r.ByteSize();

    DBG("SEND sctp_bus event request %d:%s/%d -> %d:%s seq: %ld",
        r.src_node_id(),
        r.src_session_id().c_str(),
        assoc_id,
        r.dst_node_id(),
        r.dst_session_id().c_str(),
        r.sequence());

    if(::send(fd, payload, size, SCTP_UNORDERED | MSG_NOSIGNAL) != size) {
       ERROR("send(): %m");
        sent_requests.erase(last_cseq);
        AmSessionContainer::instance()->postEvent(
            e.src_session_id,
            new SctpBusRawReply(e,SctpBusRawReply::RES_SEND_SOCKET_ERROR));
        return;
    }

    events_sent++;
}

void SctpClientConnection::send(const SctpBusRawReply &e)
{
    if(state!=Connected) {
        ERROR("attempt to send event to not connected peer %d",_id);
        return;
    }

    SctpBusPDU r;

    r.set_type(SctpBusPDU::REPLY);
    r.set_src_node_id(AmConfig.node_id);
    r.set_src_session_id(e.req.dst_session_id);
    r.set_dst_node_id(e.req.src_id);
    r.set_dst_session_id(e.req.src_session_id);
    r.set_sequence(e.req.cseq);

    r.set_payload(e.data.data(),e.data.size());

    if(!r.SerializePartialToArray(payload,sizeof(payload))){
        ERROR("event serialization failed");
        return;
    }

    ssize_t size = r.ByteSize();

    DBG("SEND sctp_bus event reply %d:%s/%d -> %d:%s",
        r.src_node_id(),
        r.src_session_id().c_str(),
        assoc_id,
        r.dst_node_id(),
        r.dst_session_id().c_str());

    if(::send(fd, payload, size, SCTP_UNORDERED | MSG_NOSIGNAL) != size) {
       ERROR("send(): %m");
       return;
    }

    events_sent++;
}

int SctpClientConnection::on_timer(time_t now)
{
    /*DBG("client on timer. state = %d, last connect: %s",
        state,timeval2str_ntp(last_connect_attempt).c_str());*/

    for(auto it = sent_requests.begin(); it != sent_requests.end(); ) {
        const sent_info &i = it->second;
        if(i.expire_time > now) {
            AmSessionContainer::instance()->postEvent(
                i.req.src_session_id,
                new SctpBusRawReply(i.req,SctpBusRawReply::RES_TIMEOUT));
            it = sent_requests.erase(it);
            continue;
        }
        ++it;
    }

    if(state==Closed
       && timerisset(&last_connect_attempt)
       && now > last_connect_attempt.tv_sec)
    {
        DBG("reconnect timeout for not connected %s:%d",
            am_inet_ntop(&addr).c_str(),am_get_port(&addr));
            return connect();
    }

    return 0;
}

void SctpClientConnection::onIncomingPDU(const SctpBusPDU &e)
{
    if(e.type()==SctpBusPDU::REQUEST) {
        DBG("got request PDU for session %s",e.dst_session_id().c_str());
        SctpBusRawRequest *r =
            new SctpBusRawRequest(
                e.src_session_id(),
                e.dst_node_id(),
                e.dst_session_id(),
                e.payload());
        r->src_id = _id;

        if(!AmSessionContainer::instance()->postEvent(e.dst_session_id(),r)) {
            DBG("failed to post SctpBusRawRequest for sesson %s",
                e.dst_session_id().c_str());
        }

    } else {
        if(!e.has_sequence()) {
            ERROR("got reply PDU without sequence. ignore it");
            return;
        }
        auto it = sent_requests.find(e.sequence());
        if(it == sent_requests.end()) {
            ERROR("reply PDU with sequence %ld has not matching sent request. ignore it",
                  e.sequence());
            return;
        }
        const SctpBusRawRequest &req = it->second.req;
        AmSessionContainer::instance()->postEvent(
            e.dst_session_id(),
            new SctpBusRawReply(
                req,
                e.payload()));
        sent_requests.erase(it);
    }
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


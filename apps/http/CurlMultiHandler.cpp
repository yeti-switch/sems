#include "CurlMultiHandler.h"
#include "log.h"

#include "defs.h"

static int socket_callback_static(CURL *e, curl_socket_t s, int what, CurlMultiHandler *cbp, void *sockp)
{
    return cbp->socket_callback(e,s,what,(int *)sockp);
}

static int timer_function_static(CURLM *multi, long timeout_ms, CurlMultiHandler *cbp)
{
    return cbp->timer_function(multi,timeout_ms);
}

CurlMultiHandler::CurlMultiHandler()
    : curl_running_handles(0),
      curl_multi(nullptr),
      hosts(0)
{ }

int CurlMultiHandler::init_curl(int epoll_fd_arg)
{
    epoll_fd = epoll_fd_arg;

    curl_timer.link(epoll_fd, true);

    if((curl_multi = curl_multi_init())==nullptr) {
        ERROR("curl_multi_init call failed");
            return -1;
    }

    multi_setopt(CURLMOPT_SOCKETFUNCTION, socket_callback_static);
    multi_setopt(CURLMOPT_SOCKETDATA, this);
    multi_setopt(CURLMOPT_TIMERFUNCTION, timer_function_static);
    multi_setopt(CURLMOPT_TIMERDATA, this);

    return 0;
}

CurlMultiHandler::~CurlMultiHandler()
{
    curl_multi_cleanup(curl_multi);
    if(hosts) curl_slist_free_all(hosts);
}

void CurlMultiHandler::check_multi_info()
{
    CURLMsg *msg;
    int msgs_left;
    CURL *easy;
    CurlConnection *c;

    CDBG("check_multi_info()");

    while ((msg = curl_multi_info_read(curl_multi, &msgs_left))) {
        CDBG("check_multi_info() msg type=%d easy=%p result=%d",msg->msg,msg->easy_handle,msg->data.result);
        if (msg->msg == CURLMSG_DONE) {
            CDBG("check_multi_info() msg done. easy=%p result=%d",msg->easy_handle,msg->data.result);
            easy = msg->easy_handle;
            curl_easy_getinfo(easy, CURLINFO_PRIVATE, &c);
            curl_multi_remove_handle(curl_multi, easy);
            c->finish(msg->data.result);
            on_connection_delete(c);
            delete c;
        }
    }
}

/*
 * epoll callbacks
 */

void CurlMultiHandler::on_timer_event()
{
    CDBG("on timer()");
    curl_timer.read();

#ifdef ENABLE_DEBUG
    CURLMcode rc =
#endif
        curl_multi_socket_action(curl_multi, CURL_SOCKET_TIMEOUT, 0, &curl_running_handles);
    CDBG("curl_multi_socket_action(CURL_SOCKET_TIMEOUT,0) = %d, running_handles = %d",
        rc,curl_running_handles);

    check_multi_info();
}

void CurlMultiHandler::on_socket_event(int socket, uint32_t events)
{
#ifdef ENABLE_DEBUG
    CURLMcode rc;
#endif
    int action = 0;

    CDBG("on_socket_event(%d, %d (%s|%s|%s))",
        socket, events,
        events&EPOLLIN ? "EPOLLIN" : "",
        events&EPOLLOUT? "EPOLLOUT" : "",
        events&EPOLLERR? "EPOLLERR" : "");

    if(events&EPOLLIN) action|= CURL_CSELECT_IN;
    if(events&EPOLLOUT) action|= CURL_CSELECT_OUT;
    if(events&EPOLLERR) action|= CURL_CSELECT_ERR;
#ifdef ENABLE_DEBUG
    rc =
#endif
        curl_multi_socket_action(curl_multi, socket, action, &curl_running_handles);
    CDBG("curl_multi_socket_action(%d, %d) = %d, running_handles = %d",
        socket,action,rc,curl_running_handles);

    check_multi_info();
}

/* * curl multi callbacks
 */

int CurlMultiHandler::socket_callback(CURL *, curl_socket_t s, int what, void *sockp)
{
#ifdef ENABLE_DEBUG
    static const char *whatstr[]={ "none", "IN", "OUT", "INOUT", "REMOVE"};
#endif
    CDBG("socket_callback(): s=%d e=%p what=%s ", s, e, whatstr[what]);

    if(CURL_POLL_NONE==what) return 0;

    if(CURL_POLL_REMOVE==what) {
        if(CURLM_OK!=curl_multi_assign(curl_multi, s, nullptr)) {
            ERROR("curl_multi_assign(%d,0)",s);
        }
        if(-1==epoll_ctl(epoll_fd, EPOLL_CTL_DEL, s, nullptr)) {
            DBG("epoll_ctl_delete(%d) %d",s,errno);
        }
        return 0;
    }

    struct epoll_event ev;
    ev.data.ptr = 0;
    ev.data.fd = s;
    ev.events = EPOLLERR;
    switch(what) {
    case CURL_POLL_IN:
        ev.events |= EPOLLIN;
        break;
    case CURL_POLL_OUT:
        ev.events |= EPOLLOUT;
        break;
    case CURL_POLL_INOUT:
        ev.events |= EPOLLOUT | EPOLLIN;
        break;
    }

    if(sockp) {
        CDBG("modify socket %d watching for events %d (%s|%s|%s)",
            s,ev.events,
            ev.events&EPOLLIN ? "EPOLLIN" : "",
            ev.events&EPOLLOUT? "EPOLLOUT" : "",
            ev.events&EPOLLERR? "EPOLLERR" : "");
        if(-1==epoll_ctl(epoll_fd, EPOLL_CTL_MOD, s, &ev)) {
            DBG("epoll_ctl_mod(%d) %d",s,errno);
        }
    } else {
        if(CURLM_OK!=curl_multi_assign(curl_multi, s, (void *)1)) {
            ERROR("curl_multi_assign(%d,1)",s);
        }
        CDBG("enable socket %d watching for events %d (%s|%s|%s)",
            s,ev.events,
            ev.events&EPOLLIN ? "EPOLLIN" : "",
            ev.events&EPOLLOUT? "EPOLLOUT" : "",
            ev.events&EPOLLERR? "EPOLLERR" : "");
        if(-1==epoll_ctl(epoll_fd, EPOLL_CTL_ADD, s, &ev)) {
            ERROR("epoll_ctl_add(%d) %d",s,errno);
        }
    }

    return 0;
}

int CurlMultiHandler::timer_function(CURLM *, long timeout_ms)
{
    CDBG("process request for timer with timeout %ld", timeout_ms);
    if(timeout_ms) {
        if(timeout_ms > 0) {
            curl_timer.set(timeout_ms*1000,false);
        } else {
            //timeout_ms < 0. disarm timer
            curl_timer.set(0,false);
        }
    } else {
        //timeout_ms == 0. means to arm timer for the shortest possible interval
        curl_timer.set(1,false);
    }

    return 0;
}

#include "CurlMultiHandler.h"
#include "log.h"

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
      curl_multi(nullptr)
{ }

int CurlMultiHandler::init_curl(int fd, CURLM *handle)
{
    epoll_fd = fd;
    curl_multi = handle;

    curl_timer.link(epoll_fd, true);

    curl_multi_setopt(curl_multi, CURLMOPT_SOCKETFUNCTION, socket_callback_static);
    curl_multi_setopt(curl_multi, CURLMOPT_SOCKETDATA, this);
    curl_multi_setopt(curl_multi, CURLMOPT_TIMERFUNCTION, timer_function_static);
    curl_multi_setopt(curl_multi, CURLMOPT_TIMERDATA, this);

    return 0;
}

CurlMultiHandler::~CurlMultiHandler() {}

/*
 * epoll callbacks
 */

void CurlMultiHandler::on_timer_event()
{
    curl_timer.read();
    curl_multi_socket_action(curl_multi, CURL_SOCKET_TIMEOUT, 0, &curl_running_handles);
}

void CurlMultiHandler::on_socket_event(int socket, uint32_t events)
{
    int action = 0;
    if(events&EPOLLIN) action|= CURL_CSELECT_IN;
    if(events&EPOLLOUT) action|= CURL_CSELECT_OUT;
    if(events&EPOLLERR) action|= CURL_CSELECT_ERR;
    curl_multi_socket_action(curl_multi, socket, action, &curl_running_handles);
}

/* * curl multi callbacks
 */

int CurlMultiHandler::socket_callback(CURL* e, curl_socket_t s, int what, void *sockp)
{
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
        if(-1==epoll_ctl(epoll_fd, EPOLL_CTL_MOD, s, &ev)) {
            DBG("epoll_ctl_mod(%d) %d",s,errno);
        }
    } else {
        if(CURLM_OK!=curl_multi_assign(curl_multi, s, (void *)1)) {
            ERROR("curl_multi_assign(%d,1)",s);
        }
        if(-1==epoll_ctl(epoll_fd, EPOLL_CTL_ADD, s, &ev)) {
            ERROR("epoll_ctl_add(%d) %d",s,errno);
        }
        set_opt_connection(e);
    }

    return 0;
}

int CurlMultiHandler::timer_function(CURLM *, long timeout_ms)
{
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

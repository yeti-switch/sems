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
      curl_multi(NULL)
{ }

int CurlMultiHandler::init_curl(int epoll_fd)
{
    curl_timer.link(epoll_fd, true);

    if((curl_multi = curl_multi_init())==NULL) {
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
            if(c->finish(msg->data.result)){
                on_requeue(c);
            }
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
#ifdef ENABLE_DEBUG
    CURLMcode rc =
#endif
        curl_multi_socket_action(curl_multi, CURL_SOCKET_TIMEOUT, 0, &curl_running_handles);
    CDBG("curl_multi_socket_action(CURL_SOCKET_TIMEOUT,0) = %d, running_handles = %d",
        rc,curl_running_handles);

    check_multi_info();

    curl_timer.read();
}


void CurlMultiHandler::on_socket_event(CurlConnection *c, uint32_t events)
{
#ifdef ENABLE_DEBUG
    CURLMcode rc;
#endif
    int action = 0;

    CDBG("on_socket_event(%p, %d (%s|%s|%s))",
        c, events,
        events&EPOLLIN ? "EPOLLIN" : "",
        events&EPOLLOUT? "EPOLLOUT" : "",
        events&EPOLLERR? "EPOLLERR" : "");

    if(events&EPOLLIN) action|= CURL_CSELECT_IN;
    if(events&EPOLLOUT) action|= CURL_CSELECT_OUT;
    if(events&EPOLLERR) action|= CURL_CSELECT_ERR;
#ifdef ENABLE_DEBUG
    rc =
#endif
        curl_multi_socket_action(curl_multi, c->socket(), action, &curl_running_handles);
    CDBG("curl_multi_socket_action(%d, %d) = %d, running_handles = %d",
        c->socket(),action,rc,curl_running_handles);

    /*if(curl_running_handles <= 0) {
        DBG("all handles done. disarm timer");
        curl_timer.set(0,false); //disarm timer
    }*/

    check_multi_info();
}

/*
 * curl multi callbacks
 */

int CurlMultiHandler::socket_callback(CURL *e, curl_socket_t s, int what, void *sockp)
{
    CurlConnection *c;
#ifdef ENABLE_DEBUG
    static const char *whatstr[]={ "none", "IN", "OUT", "INOUT", "REMOVE"};
#endif
    CDBG("socket_callback(): s=%d e=%p what=%s ", s, e, whatstr[what]);

    curl_easy_getinfo(e, CURLINFO_PRIVATE, &c);
    c->watch_socket(s,what);

    return 0;
}

int CurlMultiHandler::timer_function(CURLM *multi, long timeout_ms)
{
    CDBG("process request for timer with timeout %ld", timeout_ms);
    if(timeout_ms>0){
        curl_timer.set(timeout_ms*1000,false);
    } else {
        curl_timer.set(1,false);
    }
    return 0;
}


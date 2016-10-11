#include "CurlConnection.h"
#include "log.h"
#include "defs.h"

#include <sys/epoll.h>
#include <errno.h>

#define easy_setopt(opt,val) \
    if(CURLE_OK!=curl_easy_setopt(curl,opt,val)){ \
        ERROR("curl_easy_setopt error for option" #opt); \
        return -1; \
    }

CurlConnection::CurlConnection(int epoll_fd)
  : curl(NULL),
    epoll_fd(epoll_fd),
    //s(-1),
    socket_watched(false)
{ }

CurlConnection::~CurlConnection()
{
    if(curl) curl_easy_cleanup(curl);
}

int CurlConnection::init_curl(CURLM *curl_multi)
{
    if(!(curl=curl_easy_init())){
        ERROR("curl_easy_init call failed");
        return -1;
    }

    easy_setopt(CURLOPT_PRIVATE, this);
    easy_setopt(CURLOPT_ERRORBUFFER, curl_error);

#ifdef ENABLE_DEBUG
    easy_setopt(CURLOPT_VERBOSE, 1L);
#endif

    if(curl_multi) {
        if(CURLM_OK!=curl_multi_add_handle(curl_multi,curl)){
            ERROR("can't add handler to curl_multi");
            return -1;
        }
    }

    return 0;
}

int CurlConnection::watch_socket(int socket, int what)
{
    struct epoll_event ev;

    CDBG("watch_socket(%d,%d)",socket,what);

    s = socket;

    if(CURL_POLL_NONE==what) return 0;

    if(CURL_POLL_REMOVE==what) {
        CDBG("disable socket %d watching",s);
        if(-1==epoll_ctl(epoll_fd, EPOLL_CTL_DEL, s, NULL)) {
            DBG("epoll_ctl_delete(%d) %d",s,errno);
        }
        socket_watched = false;
        return 0;
    }

    ev.data.ptr = this;
    switch(what){
    case CURL_POLL_IN:
        ev.events = EPOLLIN | EPOLLERR;
        break;
    case CURL_POLL_OUT:
        ev.events = EPOLLOUT | EPOLLERR;
        break;
    case CURL_POLL_INOUT:
        ev.events = EPOLLOUT | EPOLLIN | EPOLLERR;
        break;
    }

    if(socket_watched) {
        CDBG("modify socket %d watching for events %d (%s|%s|%s)",
            s,ev.events,
            ev.events&EPOLLIN ? "EPOLLIN" : "",
            ev.events&EPOLLOUT? "EPOLLOUT" : "",
            ev.events&EPOLLERR? "EPOLLERR" : "");
        if(-1==epoll_ctl(epoll_fd, EPOLL_CTL_MOD, s, &ev)) {
            ERROR("epoll_ctl_mod(%d) %d",s,errno);
        }
    } else {
        CDBG("enable socket %d watching for events %d (%s|%s|%s)",
            s,ev.events,
            ev.events&EPOLLIN ? "EPOLLIN" : "",
            ev.events&EPOLLOUT? "EPOLLOUT" : "",
            ev.events&EPOLLERR? "EPOLLERR" : "");
        if(-1==epoll_ctl(epoll_fd, EPOLL_CTL_ADD, s, &ev)) {
            ERROR("epoll_ctl_add(%d) %d",s,errno);
        } else {
            socket_watched = true;
        }
    }

    return 0;
}

int CurlConnection::finish(CURLcode result)
{
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_response_code);

    if(result!=CURLE_OK)
    {
        ERROR("curl connection %p finished with error: %d (%s)",
              this, result, curl_error);
    }
    return on_finished(result);
}


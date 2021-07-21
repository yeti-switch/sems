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

int sockopt_callback(void *clientp,
                     curl_socket_t curlfd,
                     curlsocktype purpose)
{
    SOCKET_LOG("[%p] socket purpose = %d, fd = %d", clientp, purpose, curlfd);
    return CURL_SOCKOPT_OK;
}

CurlConnection::CurlConnection(int epoll_fd)
  : curl(NULL),
    epoll_fd(epoll_fd),
    //s(-1),
    socket_watched(false),
    resolve_hosts(0)
{ }

CurlConnection::~CurlConnection()
{
    if(curl) curl_easy_cleanup(curl);
    if(resolve_hosts) curl_slist_free_all(resolve_hosts);
}

static struct curl_slist* clone_resolve_slist(struct curl_slist* hosts)
{
    struct curl_slist *tmp = 0, *resolve_hosts= 0;
    while(hosts) {
        tmp = curl_slist_append(resolve_hosts, hosts->data);

        if(!tmp) {
            curl_slist_free_all(resolve_hosts);
            return NULL;
        }

        resolve_hosts = tmp;
        hosts = hosts->next;
    }
    return resolve_hosts;
}

int CurlConnection::init_curl(struct curl_slist* hosts, CURLM *curl_multi)
{
    if(!(curl=curl_easy_init())){
        ERROR("curl_easy_init call failed");
        return -1;
    }
    easy_setopt(CURLOPT_SOCKOPTFUNCTION , &sockopt_callback);
    easy_setopt(CURLOPT_SOCKOPTDATA , this);

    easy_setopt(CURLOPT_PRIVATE, this);
    easy_setopt(CURLOPT_ERRORBUFFER, curl_error);

    resolve_hosts = clone_resolve_slist(hosts);
    easy_setopt(CURLOPT_CONNECT_TO, resolve_hosts);

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
            DBG("epoll_ctl_mod(%d) %d",s,errno);
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

void CurlConnection::on_curl_error(CURLcode result)
{
    http_response_code = -result;
}

int CurlConnection::finish(CURLcode result)
{
    if(result!=CURLE_OK)
    {
        ERROR("curl connection %p finished with error: %d (%s)",
              this, result, curl_error);
        on_curl_error(result);
    } else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_response_code);
    }

    return on_finished();
}


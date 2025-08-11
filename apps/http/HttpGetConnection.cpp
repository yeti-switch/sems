#include "HttpGetConnection.h"

#include "AmUtils.h"

#include <sys/epoll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "defs.h"

#include "AmSessionContainer.h"

static size_t write_func_static(void *ptr, size_t size, size_t nmemb, HttpGetConnection *self);

HttpGetConnection::HttpGetConnection(HttpDestination &destination, const HttpGetEvent &u, const string &connection_id,
                                     int epoll_fd)
    : CurlConnection(destination, u, connection_id)
    , headers(nullptr)
{
    CDBG("HttpGetConnection() %p", this);
    u.attempt ? destination.resend_count_connection.inc() : destination.count_connection.inc();
}

HttpGetConnection::~HttpGetConnection()
{
    CDBG("~HttpGetConnection() %p curl = %p", this, curl);
    if (headers)
        curl_slist_free_all(headers);
}

int HttpGetConnection::init(struct curl_slist *hosts, CURLM *curl_multi)
{
    if (init_curl(hosts, curl_multi)) {
        ERROR("curl connection initialization failed");
        return -1;
    }

    HttpGetEvent *event_ = dynamic_cast<HttpGetEvent *>(event.get());
    easy_setopt(CURLOPT_URL, event_->url.c_str());
    easy_setopt(CURLOPT_WRITEFUNCTION, write_func_static);
    easy_setopt(CURLOPT_WRITEDATA, this);

    if (!destination.source_address.empty())
        easy_setopt(CURLOPT_INTERFACE, destination.source_address.c_str());

    return 0;
}

bool HttpGetConnection::on_failed()
{
    CurlConnection::on_failed();
    event->failover_idx = 0;
    event->attempt++;
    return false;
}

char *HttpGetConnection::get_name()
{
    static char name[] = "get";
    return name;
}

void HttpGetConnection::post_response_event()
{
    if (event->session_id.empty())
        return;
    if (!AmSessionContainer::instance()->postEvent(
            event->session_id, new HttpGetResponseEvent(http_response_code, response, mime_type, event->token)))
    {
        ERROR("failed to post HttpGetResponseEvent for session %s", event->session_id.c_str());
    }
}

const string &HttpGetConnection::get_response()
{
    return response;
}

size_t write_func_static(void *ptr, size_t size, size_t nmemb, HttpGetConnection *self)
{
    return self->write_func(ptr, size, nmemb, NULL);
}

size_t HttpGetConnection::write_func(void *ptr, size_t size, size_t nmemb, void *)
{
    int old_size = response.size();
    response.resize(old_size + size * nmemb);
    memcpy((char *)response.data() + old_size, (char *)ptr, size * nmemb);
    if (destination.max_reply_size && destination.max_reply_size < response.size())
        return 0;
    else
        return size * nmemb;
}

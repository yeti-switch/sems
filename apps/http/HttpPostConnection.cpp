#include "HttpPostConnection.h"

#include "AmUtils.h"

#include <sys/epoll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "defs.h"

#include "AmSessionContainer.h"

static size_t write_func_static(void *ptr, size_t size, size_t nmemb, HttpPostConnection *self);

HttpPostConnection::HttpPostConnection(HttpDestination &destination, const HttpPostEvent &u,
                                       const string &connection_id)
    : CurlConnection(destination, u, connection_id)
{
    CDBG("HttpPostConnection() %p", this);
    u.attempt ? destination.resend_count_connection.inc() : destination.count_connection.inc();
}

HttpPostConnection::~HttpPostConnection()
{
    CDBG("~HttpPostConnection() %p curl = %p", this, curl);
}

int HttpPostConnection::init(struct curl_slist *hosts, CURLM *curl_multi)
{
    if (init_curl(hosts, curl_multi)) {
        ERROR("curl connection initialization failed");
        return -1;
    }

    if (destination.http2_tls)
        easy_setopt(CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);

    if (!destination.certificate.empty())
        easy_setopt(CURLOPT_SSLCERT, destination.certificate.c_str());
    if (!destination.certificate_key.empty())
        easy_setopt(CURLOPT_SSLKEY, destination.certificate_key.c_str());

    easy_setopt(CURLOPT_URL, get_url().c_str());
    HttpPostEvent *event_ = dynamic_cast<HttpPostEvent *>(event.get());
    easy_setopt(CURLOPT_POSTFIELDS, event_->data.c_str());

    easy_setopt(CURLOPT_WRITEFUNCTION, write_func_static);
    easy_setopt(CURLOPT_WRITEDATA, this);

    if (!destination.source_address.empty())
        easy_setopt(CURLOPT_INTERFACE, destination.source_address.c_str());

    return 0;
}

void HttpPostConnection::run_action()
{
    if (failed)
        destination.fail_action.perform();
    else
        destination.succ_action.perform();
}

bool HttpPostConnection::on_failed()
{
    CurlConnection::on_failed();
    if (event->failover_idx < destination.max_failover_idx) {
        event->failover_idx++;
        DBG("faiolver to the next destination. new failover index is %i", event->failover_idx);
        on_finish_requeue = true;
        return true; // force requeue
    } else {
        event->failover_idx = 0;
        event->attempt++;
    }
    return false;
}

char *HttpPostConnection::get_name()
{
    static char name[] = "post";
    return name;
}

void HttpPostConnection::post_response_event()
{
    if (event->session_id.empty())
        return;
    if (!AmSessionContainer::instance()->postEvent(
            event->session_id, new HttpPostResponseEvent(http_response_code, response, event->token)))
    {
        ERROR("failed to post HttpPostResponseEvent for session %s", event->session_id.c_str());
    }
}

const string &HttpPostConnection::get_response()
{
    return response;
}

size_t write_func_static(void *ptr, size_t size, size_t nmemb, HttpPostConnection *self)
{
    return self->write_func(ptr, size, nmemb, NULL);
}

size_t HttpPostConnection::write_func(void *ptr, size_t size, size_t nmemb, void *)
{
    response += string((char *)ptr, size * nmemb);
    return size * nmemb;
}

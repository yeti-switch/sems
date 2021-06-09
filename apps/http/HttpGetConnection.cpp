#include "HttpGetConnection.h"

#include "AmUtils.h"

#include <sys/epoll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "defs.h"

#include "AmSessionContainer.h"

static size_t write_func_static(void *ptr, size_t size, size_t nmemb, HttpGetConnection *self);

HttpGetConnection::HttpGetConnection(const HttpGetEvent &u, HttpDestination &destination, int epoll_fd):
    CurlConnection(epoll_fd),
    destination(destination),
    event(u),
    headers(NULL)
{
    CDBG("HttpGetConnection() %p",this);
    u.attempt ? destination.resend_count_connection.inc() : destination.count_connection.inc();
}

HttpGetConnection::~HttpGetConnection() {
    CDBG("~HttpGetConnection() %p curl = %p",this,curl);
    if(headers) curl_slist_free_all(headers);
}

int HttpGetConnection::init(struct curl_slist* hosts, CURLM *curl_multi)
{
    if(init_curl(hosts, curl_multi)){
        ERROR("curl connection initialization failed");
        return -1;
    }

    easy_setopt(CURLOPT_URL,event.url.c_str());
    easy_setopt(CURLOPT_WRITEFUNCTION,write_func_static);
    easy_setopt(CURLOPT_WRITEDATA,this);

    return 0;
}

int HttpGetConnection::on_finished(CURLcode result)
{
    int requeue = 0;
    char *eff_url, *ct;
    double speed_download, total_time;

    event.attempt ? destination.resend_count_connection.dec() : destination.count_connection.dec();

    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &eff_url);
    curl_easy_getinfo(curl, CURLINFO_SPEED_DOWNLOAD, &speed_download);
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);
    curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct);

    DBG("get: %s finished with %ld in %.3f seconds (%.3f bytes/sec) with content type %s",
        eff_url, http_response_code,
        total_time, speed_download, ct);

    if(destination.succ_codes(http_response_code)) {
        mime_type = ct;
        requeue = destination.post_upload(false);
    } else {
        ERROR("can't get to '%s'. curl_code: %d, http_code %ld",
              eff_url,
              result,http_response_code);
        event.failover_idx = 0;
        event.attempt++;
        requeue = destination.post_upload(true);
    }

    if(requeue &&
       destination.attempts_limit &&
       event.attempt >= destination.attempts_limit)
    {
        DBG("attempt limit(%i) reached. skip requeue",
            destination.attempts_limit);
        requeue = false;
    }

    if(!requeue) {
        destination.requests_processed.inc();
        post_response_event();
    }

    return requeue;
}

void HttpGetConnection::on_requeue()
{
    if(destination.check_queue()){
        ERROR("reached max resend queue size %d. drop failed post request",destination.resend_queue_max);
        post_response_event();
    } else {
        destination.addEvent(new HttpGetEvent(event));
    }
}

void HttpGetConnection::post_response_event()
{
    if(event.session_id.empty())
        return;
    if(!AmSessionContainer::instance()->postEvent(
        event.session_id,
        new HttpGetResponseEvent(http_response_code, response, mime_type, event.token)))
    {
        ERROR("failed to post HttpGetResponseEvent for session %s",
            event.session_id.c_str());
    }
}

size_t write_func_static(void *ptr, size_t size, size_t nmemb, HttpGetConnection *self)
{
    return self->write_func(ptr,size,nmemb,NULL);
}

size_t HttpGetConnection::write_func(void *ptr, size_t size, size_t nmemb, void *)
{
    int old_size = response.size();
    response.resize(old_size + size*nmemb);
    memcpy((char*)response.data() + old_size, (char*)ptr, size*nmemb);
    return size*nmemb;
}

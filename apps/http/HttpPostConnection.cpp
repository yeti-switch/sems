#include "HttpPostConnection.h"

#include "AmUtils.h"

#include <sys/epoll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "defs.h"

#include "AmSessionContainer.h"

static size_t write_func_static(void *ptr, size_t size, size_t nmemb, HttpPostConnection *self);

HttpPostConnection::HttpPostConnection(const HttpPostEvent &u, HttpDestination &destination):
    destination(destination),
    event(u),
    headers(nullptr)
{
    CDBG("HttpPostConnection() %p",this);
    u.attempt ? destination.resend_count_connection.inc() : destination.count_connection.inc();
}

HttpPostConnection::~HttpPostConnection() {
    CDBG("~HttpPostConnection() %p curl = %p",this,curl);
    if(headers) curl_slist_free_all(headers);
}

int HttpPostConnection::init(struct curl_slist* hosts, CURLM *curl_multi)
{
    if(init_curl(hosts, curl_multi)){
        ERROR("curl connection initialization failed");
        return -1;
    }

    if(!destination.content_type.empty()) {
        string content_type_header = "Content-Type: ";
        content_type_header += destination.content_type;
        headers = curl_slist_append(headers, content_type_header.c_str());
    }

    for(auto& header : event.additional_headers) {
        string user_header = header.first + ": ";
        user_header += header.second;
        headers = curl_slist_append(headers, user_header.c_str());
    }

    if(headers) easy_setopt(CURLOPT_HTTPHEADER, headers);
    easy_setopt(CURLOPT_URL,destination.url[0].c_str());
    easy_setopt(CURLOPT_POSTFIELDS,event.data.c_str());

    easy_setopt(CURLOPT_WRITEFUNCTION,write_func_static);
    easy_setopt(CURLOPT_WRITEDATA,this);

    if(!destination.source_address.empty())
        easy_setopt(CURLOPT_INTERFACE, destination.source_address.c_str());

    return 0;
}

int HttpPostConnection::on_finished()
{
    int requeue = 0;
    char *eff_url;
    double speed_upload, total_time;

    event.attempt ? destination.resend_count_connection.dec() : destination.count_connection.dec();

    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &eff_url);
    curl_easy_getinfo(curl, CURLINFO_SPEED_UPLOAD, &speed_upload);
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);

    DBG("post: %s finished with %ld in %.3f seconds (%.3f bytes/sec)",
        eff_url, http_response_code,
        total_time, speed_upload);

    bool failed = false;
    if(destination.succ_codes(http_response_code)) {
        requeue = destination.post_upload(false);
    } else {
        failed = true;
        ERROR("can't post to '%s'. http_code %ld",
              eff_url,http_response_code);
        if(event.failover_idx < destination.max_failover_idx) {
            event.failover_idx++;
            DBG("faiolver to the next destination. new failover index is %i",
                event.failover_idx);
            return true; //force requeue
        } else {
            event.failover_idx = 0;
            event.attempt++;
        }
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
        if(failed) destination.requests_failed.inc();
        post_response_event();
    }

    return requeue;
}

void HttpPostConnection::on_requeue()
{
    if(destination.check_queue()){
        ERROR("reached max resend queue size %d. drop failed post request",destination.resend_queue_max);
        post_response_event();
    } else {
        destination.addEvent(new HttpPostEvent(event));
    }
}

void HttpPostConnection::post_response_event()
{
    if(event.session_id.empty())
        return;
    if(!AmSessionContainer::instance()->postEvent(
        event.session_id,
        new HttpPostResponseEvent(http_response_code,response,event.token)))
    {
        ERROR("failed to post HttpPostResponseEvent for session %s",
            event.session_id.c_str());
    }
}

size_t write_func_static(void *ptr, size_t size, size_t nmemb, HttpPostConnection *self)
{
    return self->write_func(ptr,size,nmemb,NULL);
}

size_t HttpPostConnection::write_func(void *ptr, size_t size, size_t nmemb, void *)
{
    response += string((char*)ptr, size*nmemb);
    return size*nmemb;
}

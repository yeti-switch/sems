#include "HttpMultipartFormConnection.h"

#include "AmUtils.h"

#include <sys/epoll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "defs.h"

#include "AmSessionContainer.h"

HttpMultiPartFormConnection::HttpMultiPartFormConnection(const HttpPostMultipartFormEvent &u, HttpDestination &destination, int epoll_fd):
    CurlConnection(epoll_fd),
    destination(destination),
    event(u),
    form(0)
{
    CDBG("HttpMultiPartFormConnection() %p",this);
    u.attempt ? destination.resend_count_connection.inc() : destination.count_connection.inc();
}

HttpMultiPartFormConnection::~HttpMultiPartFormConnection() {
    CDBG("~HttpMultiPartFormConnection() %p curl = %p",this,curl);
    if(form)
        curl_mime_free(form);
}

int HttpMultiPartFormConnection::init(struct curl_slist* hosts, CURLM *curl_multi)
{
    curl_mimepart *field;

    if(init_curl(hosts, curl_multi)) {
        ERROR("curl connection initialization failed");
        return -1;
    }

    form = curl_mime_init(curl);

    for(const auto &part : event.parts ) {
        field = curl_mime_addpart(form);
        curl_mime_name(field, part.name.c_str());
        if(!part.content_type.empty()) {
            curl_mime_type(field,part.content_type.c_str());
        }
        switch(part.type) {
        case HttpPostMultipartFormEvent::Part::ImmediateValue:
            curl_mime_data(field,part.value.c_str(),part.value.size());
            break;
        case HttpPostMultipartFormEvent::Part::FilePath:
            curl_mime_filedata(field,part.value.c_str());
            file_path = part.value;

            if(!file_exists(file_path)) {
                ERROR("HttpMultiPartFormConnection: can't open file: %s",file_path.c_str());
                curl_mime_free(form);
                form = 0;
                return -1;
            }

            file_basename = filename_from_fullpath(file_path);

            unsigned int file_size = get_file_size();
            if(destination.min_file_size && file_size < destination.min_file_size) {
                INFO("file '%s' is too small (%u < %u). skip request. perform on_success actions",
                     file_path.c_str(), file_size, destination.min_file_size);
                curl_mime_free(form);
                form = 0;
                destination.succ_action.perform(file_path, file_basename);
                return -1;
            }

            break;
        }
    }

    easy_setopt(CURLOPT_URL,destination.url[event.failover_idx].c_str());
    easy_setopt(CURLOPT_MIMEPOST,form);

    return 0;
}

static void dump_event(const HttpPostMultipartFormEvent &event)
{
    auto event_ptr = static_cast<const void *>(&event);
    ERROR("%p parts: %ld, failover_idx: %d, attempt: %d",event_ptr,
          event.parts.size(), event.failover_idx, event.attempt);
    int i = 0;
    for(const auto &part : event.parts) {
        ERROR("%p parts[%d] name: %s, type: %d, content_type: %s, value: %s",event_ptr, i,
              part.name.c_str(), part.type, part.content_type.c_str(), part.value.c_str());
        i++;
    }
}

int HttpMultiPartFormConnection::on_finished(CURLcode result)
{
    int requeue = 0;
    char *eff_url;
    double speed_upload, total_time;

    event.attempt ? destination.resend_count_connection.dec() : destination.count_connection.dec();

    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &eff_url);
    curl_easy_getinfo(curl, CURLINFO_SPEED_UPLOAD, &speed_upload);
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);

    DBG("post multipart form to %s finished with %ld in %.3f seconds (%.3f bytes/sec)",
        eff_url, http_response_code,
        total_time, speed_upload);

    if(destination.succ_codes(http_response_code)) {
        requeue = destination.post_upload(file_path,file_basename, false);
    } else {
        ERROR("failed to post multipart form to '%s'. curl_code: %d, http_code %ld. event ptr: %p",
              eff_url,result,http_response_code,static_cast<void *>(&event));
        dump_event(event);
        if(event.failover_idx < destination.max_failover_idx) {
            event.failover_idx++;
            DBG("faiolver to the next destination. new failover index is %i",
                event.failover_idx);
            return true; //force requeue
        } else {
            event.attempt++;
            event.failover_idx = 0;
        }
        requeue = destination.post_upload(file_path,file_basename,true);
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

void HttpMultiPartFormConnection::on_requeue()
{
    if(destination.check_queue()){
        ERROR("reached max resend queue size %d. drop failed multipart form request",destination.resend_queue_max);
        post_response_event();
    } else {
        destination.addEvent(new HttpPostMultipartFormEvent(event));
    }
}

void HttpMultiPartFormConnection::post_response_event()
{
    if(event.session_id.empty())
        return;
    if(!AmSessionContainer::instance()->postEvent(
        event.session_id,
        new HttpUploadResponseEvent(http_response_code,event.token)))
    {
        ERROR("failed to post HttpUploadResponseEvent for session %s",
            event.session_id.c_str());
    }
}

unsigned int HttpMultiPartFormConnection::get_file_size()
{
    struct stat buf;
    if(stat(file_path.c_str(), &buf)) return 0;
    return buf.st_size;
}


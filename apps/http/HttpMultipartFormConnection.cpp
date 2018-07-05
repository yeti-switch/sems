#include "HttpMultipartFormConnection.h"

#include "AmUtils.h"

#include <sys/epoll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "defs.h"

#include "AmSessionContainer.h"

HttpMultiPartFormConnection::HttpMultiPartFormConnection(const HttpPostMultipartFormEvent &u, const HttpDestination &destination, int epoll_fd):
    CurlConnection(epoll_fd),
    destination(destination),
    event(u)
{
    CDBG("HttpMultiPartFormConnection() %p",this);
}

HttpMultiPartFormConnection::~HttpMultiPartFormConnection() {
    CDBG("~HttpMultiPartFormConnection() %p curl = %p",this,curl);
}

int HttpMultiPartFormConnection::init(CURLM *curl_multi)
{
    curl_mime *form;
    curl_mimepart *field;

    if(init_curl(curl_multi)) {
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
            curl_mime_filename(field,part.value.c_str());
            file_path = part.value;
            file_basename = filename_from_fullpath(file_path);
            break;
        }
    }

    easy_setopt(CURLOPT_URL,destination.url[event.failover_idx].c_str());
    easy_setopt(CURLOPT_MIMEPOST,form);

    return 0;
}

int HttpMultiPartFormConnection::on_finished(CURLcode result)
{
    int requeue = 0;
    char *eff_url;
    double speed_upload, total_time;

    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &eff_url);
    curl_easy_getinfo(curl, CURLINFO_SPEED_UPLOAD, &speed_upload);
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);

    DBG("post multipart form to %s finished with %ld in %.3f seconds (%.3f bytes/sec)",
        eff_url, http_response_code,
        total_time, speed_upload);

    if(destination.succ_codes(http_response_code)) {
        requeue = destination.post_upload(file_path,file_basename, false);
    } else {
        ERROR("failed to post multipart form  to '%s'. curl_code: %d, http_code %ld",
              eff_url,result,http_response_code);
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

    if(!requeue)
        post_response_event();

    return requeue;
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


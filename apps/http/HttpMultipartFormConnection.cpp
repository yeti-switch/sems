#include "HttpMultipartFormConnection.h"

#include "AmUtils.h"

#include <sys/epoll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "defs.h"

#include "AmSessionContainer.h"

HttpMultiPartFormConnection::HttpMultiPartFormConnection(HttpDestination &destination,
                                                         const HttpPostMultipartFormEvent &u,
                                                         const string& connection_id):
    CurlConnection(destination, u, connection_id),
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

    HttpPostMultipartFormEvent* event_ = dynamic_cast<HttpPostMultipartFormEvent*>(event.get());
    for(const auto &part : event_->parts ) {
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

            unsigned int file_size = get_file_size();
            if(destination.min_file_size && file_size < destination.min_file_size) {
                INFO("file '%s' is too small (%u < %u). skip request. perform on_success actions",
                     file_path.c_str(), file_size, destination.min_file_size);
                curl_mime_free(form);
                form = 0;
                DestinationAction action = destination.succ_action;
                action.set_path(file_path);
                action.perform();
                return -1;
            }

            break;
        }
    }

    easy_setopt(CURLOPT_URL,get_url().c_str());
    easy_setopt(CURLOPT_MIMEPOST,form);

    if(!destination.source_address.empty())
        easy_setopt(CURLOPT_INTERFACE, destination.source_address.c_str());

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

bool HttpMultiPartFormConnection::on_failed()
{
    CurlConnection::on_failed();
    if(!file_path.empty())
        finish_action.set_path(file_path);
    dump_event(*dynamic_cast<HttpPostMultipartFormEvent*>(event.get()));
    if(event->failover_idx < destination.max_failover_idx) {
        event->failover_idx++;
        DBG("faiolver to the next destination. new failover index is %i",
            event->failover_idx);
        on_finish_requeue = true;
        return true; //force requeue
    } else {
        event->attempt++;
        event->failover_idx = 0;
    }
    return false;
}

bool HttpMultiPartFormConnection::on_success()
{
    CurlConnection::on_success();
    if(!file_path.empty())
        finish_action.set_path(file_path);
    return false;
}

char * HttpMultiPartFormConnection::get_name()
{
    static char name[] = "post multipart form";
    return name;
}

void HttpMultiPartFormConnection::post_response_event()
{
    if(event->session_id.empty())
        return;
    if(!AmSessionContainer::instance()->postEvent(
        event->session_id,
        new HttpUploadResponseEvent(http_response_code,event->token)))
    {
        ERROR("failed to post HttpUploadResponseEvent for session %s",
            event->session_id.c_str());
    }
}

void HttpMultiPartFormConnection::configure_headers()
{ }

unsigned int HttpMultiPartFormConnection::get_file_size()
{
    struct stat buf;
    if(stat(file_path.c_str(), &buf)) return 0;
    return buf.st_size;
}


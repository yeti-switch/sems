#include "HttpUploadConnection.h"
#include "AmUtils.h"

#include <sys/epoll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "defs.h"
#include "AmSessionContainer.h"

HttpUploadConnection::HttpUploadConnection(HttpDestination &destination, const HttpUploadEvent &u,
                                           const string &connection_id)
    : CurlConnection(destination, u, connection_id)
    , fd(nullptr)
{
    CDBG("HttpUploadConnection() %p", this);
    u.attempt ? destination.resend_count_connection.inc() : destination.count_connection.inc();
}

HttpUploadConnection::~HttpUploadConnection()
{
    CDBG("~HttpUploadConnection() %p curl = %p", this, curl);
    if (fd)
        fclose(fd);
}

int HttpUploadConnection::init(struct curl_slist *hosts, CURLM *curl_multi)
{
    struct stat file_info;

    HttpUploadEvent *event_ = dynamic_cast<HttpUploadEvent *>(event.get());
    file_basename           = filename_from_fullpath(event_->file_path);
    if (file_basename.empty()) {
        ERROR("invalid file path: %s", event_->file_path.c_str());
        return -1;
    }

    if (event_->file_name.empty()) {
        event_->file_name = file_basename;
    }

    if (!(fd = fopen(event_->file_path.c_str(), "rb"))) {
        ERROR("can't open file to upload: %s", event_->file_path.c_str());
        return -1;
    }

    if (0 != fstat(fileno(fd), &file_info)) {
        ERROR("can't stat file: %s", event_->file_path.c_str());
        return -1;
    }

    if (destination.min_file_size && file_info.st_size < destination.min_file_size) {
        INFO("file '%s' is too small (%ld < %u). skip request. perform on_success actions", event_->file_path.c_str(),
             file_info.st_size, destination.min_file_size);
        // process file indentically to the success action
        DestinationAction action = destination.succ_action;
        action.set_path(event_->file_path);
        action.perform();
        return -1;
    }

    if (init_curl(hosts, curl_multi)) {
        ERROR("curl connection initialization failed");
        return -1;
    }

    string upload_url = destination.url[event->failover_idx] + '/' + event_->file_name;

    easy_setopt(CURLOPT_URL, upload_url.c_str());
    easy_setopt(CURLOPT_UPLOAD, 1L);
    easy_setopt(CURLOPT_READDATA, fd);
    easy_setopt(CURLOPT_INFILESIZE_LARGE, (curl_off_t)file_info.st_size);

    // easy_setopt(CURLOPT_LOW_SPEED_TIME, 60L);
    // easy_setopt(CURLOPT_LOW_SPEED_LIMIT, 10L);

    if (!destination.source_address.empty())
        easy_setopt(CURLOPT_INTERFACE, destination.source_address.c_str());

    return 0;
}


bool HttpUploadConnection::on_failed()
{
    CurlConnection::on_failed();
    HttpUploadEvent *event_ = dynamic_cast<HttpUploadEvent *>(event.get());
    finish_action.set_path(event_->file_path);
    if (event->failover_idx < destination.max_failover_idx) {
        event->failover_idx++;
        DBG("faiolver to the next destination. new failover index is %i", event->failover_idx);
        on_finish_requeue = true;
        return true; // force requeue
    } else {
        event->attempt++;
        event->failover_idx = 0;
    }
    return false;
}

bool HttpUploadConnection::on_success()
{
    CurlConnection::on_success();
    HttpUploadEvent *event_ = dynamic_cast<HttpUploadEvent *>(event.get());
    finish_action.set_path(event_->file_path);
    return false;
}

char *HttpUploadConnection::get_name()
{
    static char name[] = "upload";
    return name;
}

void HttpUploadConnection::post_response_event()
{
    if (event->session_id.empty())
        return;
    if (!AmSessionContainer::instance()->postEvent(event->session_id,
                                                   new HttpUploadResponseEvent(http_response_code, event->token)))
    {
        ERROR("failed to post HttpUploadResponseEvent for session %s", event->session_id.c_str());
    }
}

#include "HttpDownloadConnection.h"
#include "AmUtils.h"

#include <cstdio>
#include <errno.h>

#include "defs.h"
#include "AmSessionContainer.h"

static size_t write_func_static(void *ptr, size_t size, size_t nmemb, HttpDownloadConnection *self)
{
    return self->write_func(ptr, size, nmemb);
}

HttpDownloadConnection::HttpDownloadConnection(const std::shared_ptr<HttpDestination> &dest, const HttpDownloadEvent &u,
                                               const string &connection_id)
    : CurlConnection(dest, u, connection_id)
    , fd(nullptr)
{
    CDBG("HttpDownloadConnection() %p", this);
    u.attempt ? dest->resend_count_connection->inc() : dest->count_connection->inc();
}

HttpDownloadConnection::~HttpDownloadConnection()
{
    CDBG("~HttpDownloadConnection() %p curl = %p", this, curl);
    close_file();
}

string HttpDownloadConnection::get_url(const HttpDestination &d, const HttpDownloadEvent &e)
{
    return d.url[e.failover_idx] + '/' + e.file_path;
}

string HttpDownloadConnection::get_local_path(const HttpDownloadEvent &e)
{
    return e.dst_dir + '/' + filename_from_fullpath(e.file_path);
}

void HttpDownloadConnection::post_error_event(const HttpDownloadEvent &e, const string &error)
{
    if (e.session_id.empty())
        return;
    if (!AmSessionContainer::instance()->postEvent(e.session_id,
                                                   new HttpDownloadResponseEvent(0, string(), error, e.token)))
    {
        ERROR("failed to post HttpDownloadResponseEvent for session %s", e.session_id.c_str());
    }
}

int HttpDownloadConnection::init(struct curl_slist *hosts, CURLM *curl_multi)
{
    HttpDownloadEvent *event_ = dynamic_cast<HttpDownloadEvent *>(event.get());

    if (filename_from_fullpath(event_->file_path).empty()) {
        ERROR("invalid download path: %s", event_->file_path.c_str());
        post_error_event(*event_, "invalid download path");
        return -1;
    }

    local_path = get_local_path(*event_);
    if (!(fd = fopen(local_path.c_str(), "wb"))) {
        ERROR("can't open file for download: %s: %m", local_path.c_str());
        post_error_event(*event_, "can't open file for download: " + local_path);
        return -1;
    }

    if (init_curl(hosts, curl_multi)) {
        ERROR("curl connection initialization failed");
        post_error_event(*event_, "curl connection initialization failed");
        return -1;
    }

    string url = get_url(destination, *event_);
    easy_setopt(CURLOPT_URL, url.c_str());
    easy_setopt(CURLOPT_WRITEFUNCTION, write_func_static);
    easy_setopt(CURLOPT_WRITEDATA, this);

    if (!destination.source_address.empty())
        easy_setopt(CURLOPT_INTERFACE, destination.source_address.c_str());

    return 0;
}

void HttpDownloadConnection::close_file()
{
    if (!fd)
        return;
    fclose(fd);
    fd = nullptr;
}

bool HttpDownloadConnection::on_failed()
{
    CurlConnection::on_failed();
    close_file();
    finish_action.set_path(local_path);

    if (error.empty()) {
        error = http_response_code < 0 ? curl_easy_strerror(static_cast<CURLcode>(-http_response_code))
                                       : "unexpected http code";
    }

    if (event->failover_idx < destination.max_failover_idx) {
        event->failover_idx++;
        DBG("failover to the next destination. new failover index is %i", event->failover_idx);
        on_finish_requeue = true;
        return true; // force requeue
    }

    event->failover_idx = 0;
    event->attempt++;
    return false;
}

bool HttpDownloadConnection::on_success()
{
    CurlConnection::on_success();
    close_file();
    finish_action.set_path(local_path);
    return false;
}

char *HttpDownloadConnection::get_name()
{
    static char name[] = "download";
    return name;
}

void HttpDownloadConnection::post_response_event()
{
    if (event->session_id.empty())
        return;

    if (!AmSessionContainer::instance()->postEvent(
            event->session_id,
            new HttpDownloadResponseEvent(http_response_code, failed ? string() : local_path, error, event->token)))
    {
        ERROR("failed to post HttpDownloadResponseEvent for session %s", event->session_id.c_str());
    }
}

void HttpDownloadConnection::get_response(AmArg &ret)
{
    CurlConnection::get_response(ret);
    if (failed)
        ret["error"] = error;
    else
        ret["file_path"] = local_path;
}

size_t HttpDownloadConnection::write_func(void *ptr, size_t size, size_t nmemb)
{
    size_t len  = size * nmemb;
    long   code = 0;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (destination.succ_codes(code))
        return fwrite(ptr, 1, len, fd);

    // error body is reported in the response event instead of the file
    if (!destination.max_reply_size || error.size() < destination.max_reply_size)
        error.append(static_cast<char *>(ptr), len);
    return len;
}

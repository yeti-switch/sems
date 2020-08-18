#include "HttpUploadConnection.h"

#include "AmUtils.h"

#include <sys/epoll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "defs.h"

#include "AmSessionContainer.h"

HttpUploadConnection::HttpUploadConnection(const HttpUploadEvent &u, HttpDestination &destination, int epoll_fd):
    CurlConnection(epoll_fd),
    destination(destination),
    event(u),
    fd(NULL)
{
    CDBG("HttpUploadConnection() %p",this);
    u.attempt ? destination.resend_count_connection.inc() : destination.count_connection.inc();
}

HttpUploadConnection::~HttpUploadConnection() {
    CDBG("~HttpUploadConnection() %p curl = %p",this,curl);
    if(fd) fclose(fd);
    event.attempt ? destination.resend_count_connection.dec() : destination.count_connection.dec();
}

int HttpUploadConnection::init(CURLM *curl_multi)
{
    struct stat file_info;

    file_basename = filename_from_fullpath(event.file_path);
    if(file_basename.empty()){
        ERROR("invalid file path: %s",event.file_path.c_str());
        return -1;
    }

    if(event.file_name.empty()){
        event.file_name = file_basename;
    }

    if(!(fd = fopen(event.file_path.c_str(), "rb"))){
        ERROR("can't open file to upload: %s",event.file_path.c_str());
        return -1;
    }

    if(0!=fstat(fileno(fd), &file_info)) {
        ERROR("can't stat file: %s",event.file_path.c_str());
        return -1;
    }

    if(init_curl(curl_multi)){
        ERROR("curl connection initialization failed");
        return -1;
    }

    string upload_url = destination.url[event.failover_idx]+'/'+event.file_name;

    easy_setopt(CURLOPT_URL,upload_url.c_str());
    easy_setopt(CURLOPT_UPLOAD, 1L);
    easy_setopt(CURLOPT_READDATA, fd);
    easy_setopt(CURLOPT_INFILESIZE_LARGE,(curl_off_t)file_info.st_size);

    //easy_setopt(CURLOPT_LOW_SPEED_TIME, 60L);
    //easy_setopt(CURLOPT_LOW_SPEED_LIMIT, 10L);

    return 0;
}

int HttpUploadConnection::on_finished(CURLcode result)
{
    int requeue = 0;
    char *eff_url;
    double speed_upload, total_time;

    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &eff_url);
    curl_easy_getinfo(curl, CURLINFO_SPEED_UPLOAD, &speed_upload);
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);

    DBG("upload: %s => %s finished with %ld in %.3f seconds (%.3f bytes/sec)",
        event.file_path.c_str(), eff_url, http_response_code,
        total_time, speed_upload);

    if(destination.succ_codes(http_response_code)) {
        requeue = destination.post_upload(event.file_path,file_basename, false);
    } else {
        ERROR("can't upload '%s' to '%s'. curl_code: %d, http_code %ld",
              event.file_path.c_str(), eff_url,
              result,http_response_code);
        if(event.failover_idx < destination.max_failover_idx) {
            event.failover_idx++;
            DBG("faiolver to the next destination. new failover index is %i",
                event.failover_idx);
            return true; //force requeue
        } else {
            if(!event.attempt) {
                destination.count_connection.dec();
                destination.resend_count_connection.inc();
            }
            event.attempt++;
            event.failover_idx = 0;
        }
        requeue = destination.post_upload(event.file_path,file_basename,true);
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

void HttpUploadConnection::on_requeue()
{
    if(destination.check_queue()){
        ERROR("reached max resend queue size %d. drop failed upload request",destination.resend_queue_max);
        post_response_event();
    } else {
        destination.addEvent(new HttpUploadEvent(event));
    }
}

void HttpUploadConnection::post_response_event()
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


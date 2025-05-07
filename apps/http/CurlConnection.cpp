#include "CurlConnection.h"
#include "HttpClient.h"
#include "log.h"
#include "defs.h"
#include "format_helper.h"

#include <sys/epoll.h>
#include <errno.h>

#include <regex>
#include <sstream>

#define easy_setopt(opt,val) \
    if(CURLE_OK!=curl_easy_setopt(curl,opt,val)){ \
        ERROR("curl_easy_setopt error for option" #opt); \
        return -1; \
    }

int sockopt_callback(void *clientp,
                     curl_socket_t curlfd,
                     curlsocktype purpose)
{
    SOCKET_LOG("[%p] socket purpose = %d, fd = %d", clientp, purpose, curlfd);
    return CURL_SOCKOPT_OK;
}

static int curl_debugfunction_callback(
    [[maybe_unused]] CURL *handle, [[maybe_unused]] curl_infotype type,
    [[maybe_unused]] char *data, [[maybe_unused]] size_t size,
    [[maybe_unused]] void *userp)
{
    return 0;
}

CurlConnection::CurlConnection(HttpDestination& destination,
                               const HttpEvent& event,
                               const string& connection_id)
  : curl(nullptr),
    resolve_hosts(0),
    headers(nullptr),
    destination(destination),
    event(event.http_clone()),
    connection_id(connection_id),
    finished(false)
{ }

CurlConnection::~CurlConnection()
{
    if(curl) curl_easy_cleanup(curl);
    if(resolve_hosts) curl_slist_free_all(resolve_hosts);
    if(headers) curl_slist_free_all(headers);
}

static struct curl_slist* clone_resolve_slist(struct curl_slist* hosts)
{
    struct curl_slist *tmp = 0, *resolve_hosts= 0;
    while(hosts) {
        tmp = curl_slist_append(resolve_hosts, hosts->data);

        if(!tmp) {
            curl_slist_free_all(resolve_hosts);
            return NULL;
        }

        resolve_hosts = tmp;
        hosts = hosts->next;
    }
    return resolve_hosts;
}

int CurlConnection::init_curl(struct curl_slist* hosts, CURLM *curl_multi)
{
    if(!(curl=curl_easy_init())){
        ERROR("curl_easy_init call failed");
        return -1;
    }
    easy_setopt(CURLOPT_SOCKOPTFUNCTION , &sockopt_callback);
    easy_setopt(CURLOPT_SOCKOPTDATA , this);

    easy_setopt(CURLOPT_PRIVATE, this);
    easy_setopt(CURLOPT_ERRORBUFFER, curl_error);

    if(!destination.auth_usrpwd.empty())
        easy_setopt(CURLOPT_USERPWD, destination.auth_usrpwd.c_str());

    resolve_hosts = clone_resolve_slist(hosts);
    easy_setopt(CURLOPT_CONNECT_TO, resolve_hosts);
#ifdef ENABLE_DEBUG
    easy_setopt(CURLOPT_VERBOSE, 1L);
#else
    //ensure we never print to the stdout
    easy_setopt(CURLOPT_DEBUGFUNCTION, curl_debugfunction_callback);
#endif

    easy_setopt(CURLOPT_TCP_KEEPALIVE, 1L);

    for(auto it = destination.http_headers.rbegin(); it != destination.http_headers.rend(); ++it)
        headers = curl_slist_append(headers, it->c_str());

    for(auto& [hdr_name,hdr_value] : event.get()->headers) {
        headers = curl_slist_append(headers,
            format("{}: {}", hdr_name, hdr_value).data());
    }

    configure_headers();

    if(headers) easy_setopt(CURLOPT_HTTPHEADER, headers);

    if(curl_multi) {
        if(CURLM_OK!=curl_multi_add_handle(curl_multi,curl)){
            ERROR("can't add handler to curl_multi");
            return -1;
        }
    }

    return 0;
}

void CurlConnection::configure_headers()
{
    if(!destination.content_type.empty()) {
        headers = curl_slist_append(headers,
            format("Content-Type: {}", destination.content_type).data());
    }
}

void CurlConnection::on_curl_error(CURLcode result)
{
    http_response_code = -result;
}

void CurlConnection::finish(CURLcode result)
{
    if(result!=CURLE_OK)
    {
        ERROR("curl connection %p finished with error: %d (%s)",
              this, result, curl_error);
        on_curl_error(result);
    } else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_response_code);
    }

    event->attempt ? destination.resend_count_connection.dec() : destination.count_connection.dec();
    if(need_requeue())
        on_requeue();
    on_finished();
}

bool CurlConnection::need_requeue()
{
    if(destination.succ_codes(http_response_code)) {
        failed = false;
        if(on_success()) return on_finish_requeue;
        else on_finish_requeue = destination.succ_action.requeue();
    } else {
        failed = true;
        if(on_failed()) return on_finish_requeue;
        on_finish_requeue = destination.fail_action.requeue();
    }

    if(on_finish_requeue &&
       destination.attempts_limit &&
       event->attempt >= destination.attempts_limit)
    {
        if (HttpClient::events_log_level >= 0) {
            _LOG(HttpClient::events_log_level,
                "attempt limit(%i) reached. skip requeue",
                destination.attempts_limit);
        }
        on_finish_requeue = false;
    }

    return on_finish_requeue;
}

string CurlConnection::get_url()
{
    string url = destination.url[event->failover_idx];
    for(auto& [name,value]: event->url_placeholders) {
        char *escaped = curl_easy_escape(
            curl, value.data(),value.size());
        try {
            std::ostringstream oss;
            oss << "\\{" << name << "\\}";
            url = std::regex_replace(url, std::regex(oss.str()), escaped);
        } catch(std::regex_error &e) {
            ERROR("failed to replace url_placeholder %s => %s: %s",
                name.data(), value.data(), e.what());
        }
        curl_free(escaped);
    }
    return url;
}

void CurlConnection::on_finished()
{
    char *eff_url, *ct;
    double speed_download;

    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &eff_url);
    curl_easy_getinfo(curl, CURLINFO_SPEED_DOWNLOAD, &speed_download);
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);
    curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct);

    if (HttpClient::events_log_level >= 0) {
        _LOG(HttpClient::events_log_level,
            "%s: %p %s finished with %ld in %.3f seconds (%.3f bytes/sec) with content type %s",
            get_name(), this, eff_url, http_response_code,
            total_time, speed_download, ct ? ct : "(null)");
    }

    if(destination.succ_codes(http_response_code)) {
        if(ct) mime_type = ct;
    } else {
        ERROR("%s failed for '%s'. http_code %ld",
              get_name(), eff_url, http_response_code);
    }

    destination.on_finish(failed, get_response());

    if(!on_finish_requeue) {
        destination.requests_processed.inc();
        if(failed) destination.requests_failed.inc();
        post_response_event();
    }
    finished = true;
}

void CurlConnection::on_requeue()
{
    if(destination.check_queue()){
        ERROR("reached max resend queue size %d. drop failed %s request",destination.resend_queue_max, get_name());
        post_response_event();
    } else {
        destination.addEvent(event.release());
        event = 0;
    }
}

bool CurlConnection::on_failed()
{
    finish_action = destination.fail_action;
    return false;
}

bool CurlConnection::on_success()
{
    finish_action = destination.succ_action;
    return false;
}

void CurlConnection::get_response(AmArg& ret)
{
    ret["http_code"] = http_response_code;
    ret["mime_type"] = mime_type;
    ret["total_time"] = total_time;
    ret["result"] = failed ? "failed" : "success";
    //ret["data"] = get_response();
}

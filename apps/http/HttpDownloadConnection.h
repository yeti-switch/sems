#pragma once

#include "HttpDestination.h"
#include "HttpClientAPI.h"
#include "CurlConnection.h"

class HttpDownloadConnection : public CurlConnection {
    string local_path;
    FILE  *fd;
    string error; // reason on failure. http error body if any

    void close_file();

  protected:
    bool  on_failed() override;
    bool  on_success() override;
    char *get_name() override;
    void  post_response_event() override;

  public:
    HttpDownloadConnection(const std::shared_ptr<HttpDestination> &destination, const HttpDownloadEvent &u,
                           const string &connection_id);
    ~HttpDownloadConnection();

    int init(struct curl_slist *hosts, CURLM *curl_multi);

    size_t write_func(void *ptr, size_t size, size_t nmemb);

    void get_response(AmArg &ret) override;

    static string get_url(const HttpDestination &d, const HttpDownloadEvent &e);
    static string get_local_path(const HttpDownloadEvent &e);

    /** for failures detected before the connection is created */
    static void post_error_event(const HttpDownloadEvent &e, const string &error);
};

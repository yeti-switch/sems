#pragma once

#include "curl/curl.h"
#include "stdint.h"

#include "HttpDestination.h"
#include "HttpClientAPI.h"
#include "CurlConnection.h"

class HttpPostConnection : public CurlConnection {
    string response;

  protected:
    bool          on_failed() override;
    char         *get_name() override;
    void          post_response_event() override;
    const string &get_response() override;

  public:
    HttpPostConnection(HttpDestination &destination, const HttpPostEvent &u, const string &connection_id);
    ~HttpPostConnection();

    int init(struct curl_slist *hosts, CURLM *curl_multi);

    void run_action();

    size_t write_func(void *ptr, size_t size, size_t nmemb, void *);
};

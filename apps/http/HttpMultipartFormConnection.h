#pragma once

#include "curl/curl.h"
#include "stdint.h"

#include "HttpDestination.h"
#include "HttpClientAPI.h"
#include "CurlConnection.h"

class HttpMultiPartFormConnection : public CurlConnection {
    int        response_code;
    string     file_path;
    curl_mime *form;

    unsigned int get_file_size();

  protected:
    bool  on_failed() override;
    bool  on_success() override;
    char *get_name() override;
    void  post_response_event() override;
    void  configure_headers() override;

  public:
    HttpMultiPartFormConnection(HttpDestination &destination, const HttpPostMultipartFormEvent &u,
                                const string &connection_id);
    ~HttpMultiPartFormConnection();

    int init(struct curl_slist *hosts, CURLM *curl_multi);
};

#pragma once

#include "HttpDestination.h"
#include "HttpClientAPI.h"
#include "CurlConnection.h"

class HttpUploadConnection : public CurlConnection {
    string file_basename;
    FILE  *fd;

  protected:
    bool  on_failed();
    bool  on_success();
    char *get_name();
    void  post_response_event();

  public:
    HttpUploadConnection(HttpDestination &destination, const HttpUploadEvent &u, const string &connection_id);
    ~HttpUploadConnection();

    int init(struct curl_slist *hosts, CURLM *curl_multi);

    void run_action();
};

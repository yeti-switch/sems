#pragma once

#include "curl/curl.h"
#include "stdint.h"

#include "HttpDestination.h"
#include "HttpClientAPI.h"
#include "CurlConnection.h"

class HttpGetConnection: public CurlConnection
{
  struct curl_slist *headers;
  string response;
protected:
  bool on_failed() override;
  char* get_name() override;
  void post_response_event() override;
  const string &get_response() override;
public:
  HttpGetConnection(HttpDestination &destination,
                    const HttpGetEvent &u,
                    const string& connection_id,
                    int epoll_fd);
  ~HttpGetConnection();

  int init(struct curl_slist* hosts, CURLM *curl_multi);

  size_t write_func(void *ptr, size_t size, size_t nmemb, void *);
};



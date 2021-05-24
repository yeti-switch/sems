#pragma once

#include "curl/curl.h"
#include "stdint.h"

#include "HttpDestination.h"
#include "HttpClientAPI.h"
#include "CurlConnection.h"

class HttpGetConnection: public CurlConnection
{
  HttpDestination &destination;
  HttpGetEvent event;
  int response_code;
  struct curl_slist *headers;
  string response;
  string mime_type;
public:
  HttpGetConnection(const HttpGetEvent &u, HttpDestination &destination, int epoll_fd);
  ~HttpGetConnection();

  int init(struct curl_slist* hosts, CURLM *curl_multi);

  int on_finished(CURLcode result);
  void on_requeue();

  void post_response_event();

  size_t write_func(void *ptr, size_t size, size_t nmemb, void *);
};



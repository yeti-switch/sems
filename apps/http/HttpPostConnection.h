#pragma once

#include "curl/curl.h"
#include "stdint.h"

#include "HttpDestination.h"
#include "HttpClientAPI.h"
#include "CurlConnection.h"

class HttpPostConnection: public CurlConnection
{
  const HttpDestination &destination;
  HttpPostEvent event;
  int response_code;
  struct curl_slist *headers;
  string response;
public:
  HttpPostConnection(const HttpPostEvent &u, const HttpDestination &destination, int epoll_fd);
  ~HttpPostConnection();

  const HttpPostEvent &get_event() { return event; }

  int init(CURLM *curl_multi);

  int on_finished(CURLcode result);

  void post_response_event();

  size_t write_func(void *ptr, size_t size, size_t nmemb, void *);
};


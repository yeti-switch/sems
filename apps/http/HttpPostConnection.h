#pragma once

#include "curl/curl.h"
#include "stdint.h"

#include "HttpDestination.h"
#include "HttpClientAPI.h"
#include "CurlConnection.h"

class HttpPostConnection: public CurlConnection
{
  HttpDestination &destination;
  HttpPostEvent event;
  int response_code;
  struct curl_slist *headers;
  string response;
public:
  HttpPostConnection(const HttpPostEvent &u, HttpDestination &destination);
  ~HttpPostConnection();

  int init(struct curl_slist* hosts, CURLM *curl_multi);

  int on_finished();
  void on_requeue();

  void post_response_event();

  size_t write_func(void *ptr, size_t size, size_t nmemb, void *);
};


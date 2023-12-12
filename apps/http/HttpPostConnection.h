#pragma once

#include "curl/curl.h"
#include "stdint.h"

#include "HttpDestination.h"
#include "HttpClientAPI.h"
#include "CurlConnection.h"

class HttpPostConnection: public CurlConnection
{
  struct curl_slist *headers;
  string response;
protected:
  bool on_failed();
  char* get_name();
  void post_response_event();
  const char* get_response_data();
public:
  HttpPostConnection(HttpDestination &destination,
                     const HttpPostEvent &u,
                     const string& connection_id);
  ~HttpPostConnection();

  int init(struct curl_slist* hosts, CURLM *curl_multi);

  void run_action();

  size_t write_func(void *ptr, size_t size, size_t nmemb, void *);
};


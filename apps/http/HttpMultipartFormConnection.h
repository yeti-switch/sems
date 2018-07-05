#pragma once

#include "curl/curl.h"
#include "stdint.h"

#include "HttpDestination.h"
#include "HttpClientAPI.h"
#include "CurlConnection.h"

class HttpMultiPartFormConnection: public CurlConnection
{
  const HttpDestination &destination;
  HttpPostMultipartFormEvent event;
  int response_code;
  string file_path;
  string file_basename;

public:
  HttpMultiPartFormConnection(const HttpPostMultipartFormEvent &u, const HttpDestination &destination, int epoll_fd);
  ~HttpMultiPartFormConnection();

  const HttpPostMultipartFormEvent &get_event() { return event; }

  int init(CURLM *curl_multi);

  int on_finished(CURLcode result);

  void post_response_event();
};


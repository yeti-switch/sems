#pragma once

#include "curl/curl.h"
#include "stdint.h"

#include "HttpDestination.h"
#include "HttpClientAPI.h"
#include "CurlConnection.h"

class HttpMultiPartFormConnection: public CurlConnection
{
  HttpDestination &destination;
  HttpPostMultipartFormEvent event;
  int response_code;
  string file_path;
  string file_basename;
  curl_mime *form;

public:
  HttpMultiPartFormConnection(const HttpPostMultipartFormEvent &u, HttpDestination &destination, int epoll_fd);
  ~HttpMultiPartFormConnection();

  const HttpPostMultipartFormEvent &get_event() { return event; }

  int init(CURLM *curl_multi);

  int on_finished(CURLcode result);
  void on_requeue();

  void post_response_event();
};


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

  unsigned int get_file_size();
public:
  HttpMultiPartFormConnection(const HttpPostMultipartFormEvent &u, HttpDestination &destination, int epoll_fd);
  ~HttpMultiPartFormConnection();

  const HttpPostMultipartFormEvent &get_event() { return event; }

  int init(struct curl_slist* hosts, CURLM *curl_multi);

  int on_finished(CURLcode result);
  void on_requeue();

  void post_response_event();
};


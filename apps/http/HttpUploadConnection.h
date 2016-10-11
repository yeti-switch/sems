#pragma once

#include "curl/curl.h"
#include "stdint.h"

#include "HttpDestination.h"
#include "HttpClientAPI.h"
#include "CurlConnection.h"

class HttpUploadConnection: public CurlConnection
{
  const HttpDestination &destination;
  HttpUploadEvent event;
  string file_basename;
  int response_code;
  FILE *fd;

public:
  HttpUploadConnection(const HttpUploadEvent &u, const HttpDestination &destination, int epoll_fd);
  ~HttpUploadConnection();

  const HttpUploadEvent &get_event() { return event; }

  int init(CURLM *curl_multi);

  int on_finished(CURLcode result);

  void post_response_event();
};


#pragma once

#include "curl/curl.h"
#include "stdint.h"

#include "HttpDestination.h"
#include "HttpClientAPI.h"
#include "CurlConnection.h"

class HttpUploadConnection: public CurlConnection
{
  HttpDestination &destination;
  HttpUploadEvent event;
  string file_basename;
  int response_code;
  FILE *fd;

public:
  HttpUploadConnection(const HttpUploadEvent &u, HttpDestination &destination);
  ~HttpUploadConnection();

  int init(struct curl_slist* hosts, CURLM *curl_multi);

  int on_finished();
  void on_requeue();

  void post_response_event();

};


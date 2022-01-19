#pragma once

#include "curl/curl.h"
#include "stdint.h"
#include <set>

class CurlConnection
{
  int epoll_fd;
  std::set<int> sockets;
  char curl_error[CURL_ERROR_SIZE];
protected:
  CURL *curl;
  struct curl_slist* resolve_hosts;
  long http_response_code;
public:
  CurlConnection(int epoll_fd);
  virtual ~CurlConnection();

  int init_curl(struct curl_slist* hosts, CURLM *curl_multi = NULL);
  int watch_socket(int socket, int what);

  int finish(CURLcode result);

  virtual int on_finished() = 0;
  virtual void on_requeue() = 0;
  virtual void on_curl_error(CURLcode result);
};


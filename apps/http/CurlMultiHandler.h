#pragma once

#include "AmThread.h"

#include <curl/curl.h>
#include <stdint.h>

#include "CurlConnection.h"

class CurlMultiHandler
{
  void check_multi_info();

protected:
  int curl_running_handles;
  CURLM *curl_multi;
  AmTimerFd curl_timer;

  virtual void on_connection_delete(CurlConnection *c) {}

public:
  CurlMultiHandler();
  virtual ~CurlMultiHandler();

  int init_curl(int epoll_fd);

  virtual void on_requeue(CurlConnection *c) {}

  //epoll callbacks
  void on_timer_event();
  void on_socket_event(CurlConnection *c, uint32_t events);

  //curl multi callbacks
  int socket_callback(CURL *e, curl_socket_t s, int what, void *sockp);
  int timer_function(CURLM *multi, long timeout_ms);

};


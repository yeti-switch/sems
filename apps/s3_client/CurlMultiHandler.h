#pragma once

#include "AmThread.h"

#include <curl/curl.h>
#include <stdint.h>

class CurlMultiHandler {
  protected:
    int       curl_running_handles;
    int       epoll_fd;
    CURLM    *curl_multi;
    AmTimerFd curl_timer;

    virtual void set_opt_connection(CURL *curl) {};

  public:
    CurlMultiHandler();
    virtual ~CurlMultiHandler();

    int init_curl(int epoll_fd, CURLM *curl_multi);

    // epoll callbacks
    void on_timer_event();
    void on_socket_event(int socket, uint32_t events);

    // curl multi callbacks
    int socket_callback(CURL *e, curl_socket_t s, int what, void *sockp);
    int timer_function(CURLM *, long timeout_ms);
};

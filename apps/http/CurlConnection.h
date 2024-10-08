#pragma once

#include "HttpDestination.h"
#include "curl/curl.h"
#include "stdint.h"
#include <set>

class CurlConnection
{
  char curl_error[CURL_ERROR_SIZE];
protected:
  CURL *curl;
  struct curl_slist* resolve_hosts;
  struct curl_slist *headers;

  HttpDestination& destination;
  std::unique_ptr<HttpEvent> event;
  string connection_id;

  //response variables
  long http_response_code;
  string mime_type;
  double total_time;
  bool finished;
  bool failed;
  bool on_finish_requeue;
  DestinationAction finish_action;

  string get_url();

  void on_finished();
  bool need_requeue();
  void on_requeue();

  virtual bool on_success();
  virtual bool on_failed();
  virtual const string &get_response() {
    static string empty_string;
    return empty_string;
  }
  virtual void post_response_event() = 0;
  virtual char* get_name() = 0;
  virtual void configure_headers();

public:
  CurlConnection(HttpDestination& destination,
                 const HttpEvent& event,
                 const string& connection_id);
  virtual ~CurlConnection();

  int init_curl(struct curl_slist* hosts, CURLM *curl_multi = NULL);

  void finish(CURLcode result);
  bool is_requeue() { return on_finish_requeue; }
  const char* get_connection_id() { return  connection_id.c_str(); }
  void on_curl_error(CURLcode result);
  DestinationAction get_action() { return finished ? finish_action : DestinationAction(); }
  void run_action() { if(finished) finish_action.perform(); }
  bool is_failed() { return failed; }
  void get_response(AmArg& ret);
};


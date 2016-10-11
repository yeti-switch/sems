#pragma once

#include "ampi/HttpClientAPI.h"

#include "AmApi.h"
#include "AmEventDispatcher.h"

#include "AmEventFdQueue.h"

#include "HttpDestination.h"
#include "HttpUploadConnection.h"
#include "HttpPostConnection.h"
#include "CurlMultiHandler.h"

#include <string>
#include <map>
using std::string;
using std::map;

#include "invalid_ptrs.h"

class HttpClient
: public AmDynInvokeFactory,
  public AmThread,
  public AmEventFdQueue,
  public AmEventHandler,
  public AmDynInvoke,
  public CurlMultiHandler
{
    static HttpClient* _instance;

    AmEventFd stop_event;
    AmCondition<bool> stopped;

    int epoll_fd;
    invalid_ptrs_t invalid_ptrs;

    std::queue<HttpUploadEvent *> failed_upload_events;
    std::queue<HttpPostEvent *> failed_post_events;
    AmTimerFd resend_timer;
    int resend_interval;
    unsigned int resend_queue_max;

    int configure();
    int init();

    HttpDestinationsMap destinations;

    void on_upload_request(const HttpUploadEvent &u);
    void on_post_request(const HttpPostEvent &u);
    void on_requeue(CurlConnection *c);
    void on_resend_timer_event();

    void showStats(AmArg &ret);

  public:
    HttpClient(const string& name);
    ~HttpClient();

    static HttpClient* instance();
    AmDynInvoke* getInstance() { return instance(); }

    void invoke(const string& method,
                const AmArg& args, AmArg& ret);

    int onLoad();

    void run();
    void on_stop();

    void process(AmEvent* ev);

    void on_connection_delete(CurlConnection *c);
};


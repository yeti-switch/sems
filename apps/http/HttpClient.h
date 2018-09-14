#pragma once

#include "ampi/HttpClientAPI.h"

#include "AmApi.h"
#include "AmEventDispatcher.h"

#include "AmEventFdQueue.h"

#include "HttpDestination.h"
#include "HttpUploadConnection.h"
#include "HttpPostConnection.h"
#include "HttpMultipartFormConnection.h"
#include "CurlMultiHandler.h"

#include <string>
#include <map>
#include <unordered_map>
using std::string;
using std::map;

#include "invalid_ptrs.h"

class HttpClient
: public AmThread,
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
    std::queue<HttpPostMultipartFormEvent *> failed_multipart_form_events;
    AmTimerFd resend_timer;
    int resend_interval;
    unsigned int resend_queue_max;

    struct SyncContextData {
        time_t created_at;
        int counter;
        std::queue<AmEvent *> postponed_events;

        SyncContextData(int counter)
          : counter(counter),
            created_at(time(nullptr))
        {}

        SyncContextData(AmEvent *event)
          : counter(1),
            created_at(time(nullptr))
        {
            postponed_events.push(event);
        }

        void add_event(AmEvent *event) {
            counter++;
            postponed_events.push(event);
        }
    };
    using SyncContextsMap = std::unordered_map<string, SyncContextData>;
    SyncContextsMap sync_contexts;
    AmTimerFd sync_contexts_timer;

    int configure();
    int init();

    HttpDestinationsMap destinations;

    void on_upload_request(const HttpUploadEvent &u);
    void on_post_request(const HttpPostEvent &u);
    void on_multpart_form_request(const HttpPostMultipartFormEvent &u);
    void on_trigger_sync_context(const HttpTriggerSyncContext &e);
    void on_sync_context_timer();
    void on_requeue(CurlConnection *c);
    void on_resend_timer_event();

    void showStats(AmArg &ret);
    void postRequest(const AmArg& args, AmArg& ret);

    /* true if event consumed */
    template<typename EventType>
    bool check_http_event_sync_ctx(const EventType &u);

  public:
    HttpClient();
    ~HttpClient();

    static HttpClient* instance();
    AmDynInvoke* getInstance() { return instance(); }

    void invoke(const string& method,
                const AmArg& args, AmArg& ret);

    int onLoad();

    void run();
    void on_stop();

    void process(AmEvent* ev);
    void process_http_event(AmEvent* ev);

    void on_connection_delete(CurlConnection *c);
};


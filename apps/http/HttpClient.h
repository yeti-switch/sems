#pragma once

#include "ampi/HttpClientAPI.h"

#include "AmApi.h"
#include "RpcTreeHandler.h"
#include "AmEventDispatcher.h"

#include "AmEventFdQueue.h"

#include "HttpDestination.h"
#include "HttpUploadConnection.h"
#include "HttpPostConnection.h"
#include "HttpGetConnection.h"
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
  public RpcTreeHandler<HttpClient>,
  public CurlMultiHandler
{
    friend class HttpClientFactory;
    static HttpClient* _instance;

    AmEventFd stop_event;
    AmCondition<bool> stopped;

    int epoll_fd;

    AmTimerFd resend_timer;
    int resend_interval;
    unsigned int resend_queue_max;
    unsigned int resend_connection_limit;
    unsigned int connection_limit;

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
    AmTimerFd resolve_timer;

    int configure(const string& config);
    int init();

    HttpDestinationsMap destinations;

    friend struct HttpDestination;
    void on_upload_request(HttpUploadEvent *u);
    void on_post_request(HttpPostEvent *u);
    void on_multpart_form_request(HttpPostMultipartFormEvent *u);
    void on_get_request(HttpGetEvent *e);
    void on_trigger_sync_context(const HttpTriggerSyncContext &e);
    void on_sync_context_timer();
    void on_resend_timer_event();
    void update_resolve_list();

    rpc_handler showStats;
    rpc_handler postRequest;
    rpc_handler getRequest;
    rpc_handler dstDump;
    async_rpc_handler showDnsCache;
    rpc_handler resetDnsCache;

    /* true if event consumed */
    template<typename EventType>
    bool check_http_event_sync_ctx(const EventType &u);

    bool reloadCache();
  public:
    HttpClient();
    ~HttpClient();

    static HttpClient* instance();
    static void dispose();
    AmDynInvoke* getInstance() { return static_cast<AmDynInvoke*>(instance()); }

    int onLoad();

    void run();
    void on_stop();

    void process(AmEvent* ev);
    void process_jsonrpc_request(JsonRpcRequestEvent &request);
    void process_http_event(AmEvent* ev);

    void on_connection_delete(CurlConnection *c);
    void init_rpc_tree();
};


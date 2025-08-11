#pragma once

#include "ampi/HttpClientAPI.h"

#include "AmApi.h"
#include "RpcTreeHandler.h"
#include "AmEventFdQueue.h"
#include "HttpDestination.h"
#include "CurlMultiHandler.h"
#include "ShutdownHandler.h"

#include <string>
#include <map>
#include <unordered_map>
using std::map;
using std::string;

class HttpClient : public AmThread,
                   public AmEventFdQueue,
                   public AmEventHandler,
                   public RpcTreeHandler<HttpClient>,
                   public ShutdownHandler,
                   public CurlMultiHandler {
    friend class HttpClientFactory;
    static HttpClient *_instance;

    AmEventFd         stop_event;
    AmCondition<bool> stopped;

    int epoll_fd;

    AmTimerFd    resend_timer;
    int          resend_interval;
    unsigned int resend_queue_max;
    unsigned int resend_connection_limit;
    unsigned int connection_limit;

    struct SyncContextData {
        time_t                created_at;
        int                   counter;
        std::queue<AmEvent *> postponed_events;

        SyncContextData(int counter)
            : created_at(time(nullptr))
            , counter(counter)
        {
        }

        SyncContextData(AmEvent *event)
            : created_at(time(nullptr))
            , counter(1)
        {
            postponed_events.push(event);
        }

        void add_event(AmEvent *event)
        {
            counter++;
            postponed_events.push(event);
        }
    };
    using SyncContextsMap = std::unordered_map<string, SyncContextData>;
    SyncContextsMap sync_contexts;
    AmTimerFd       auth_timer;
    AmTimerFd       sync_contexts_timer;
    AmTimerFd       resolve_timer;

    struct MultiDataEntry {
        string sync_token;
        string token;
        string session_id;
        MultiDataEntry(string sync_token, string token, string session_id)
            : sync_token(sync_token)
            , token(token)
            , session_id(session_id)
        {
        }
    };
    using MultiDataEntryMap = std::unordered_map<string, MultiDataEntry>;
    /* contexts for each event in the HttpMultiEvent
     * see:
     *  HttpClient::on_multi_request
     *  HttpClient::checkMultiResponse
     */
    MultiDataEntryMap multi_data_entries;

    struct SyncMultiData {
        unsigned int                   counter;
        std::vector<DestinationAction> actions;

        SyncMultiData(unsigned int counter)
            : counter(counter)
        {
        }
    };
    using SyncMultiDataMap = std::unordered_map<string, SyncMultiData>;
    /* sync contexts for Upload, Post, MultiPartForm events in the HttpMultiEvent
     * to trigger destinations finalization actions */
    SyncMultiDataMap sync_multies;

    using RpcRequestsMap = std::unordered_map<string, JsonRpcRequestEvent>;
    RpcRequestsMap rpc_requests;

    using HttpAuthsMap = std::map<string, HttpDestination *>;

    HttpAuthsMap        auths;
    HttpDestinationsMap destinations;

    int configure(const string &config);
    int init();

    friend struct HttpAuth;
    friend struct HttpDestination;
    void on_upload_request(HttpUploadEvent *u);
    void on_post_request(HttpPostEvent *u);
    void on_multpart_form_request(HttpPostMultipartFormEvent *u);
    void on_get_request(HttpGetEvent *e);
    void on_init_connection_error(const string &conn_id);
    void on_multi_request(HttpMultiEvent *e);
    void on_trigger_sync_context(const HttpTriggerSyncContext &e);
    void on_auth_timer();
    void on_sync_context_timer();
    void on_resend_timer_event();
    void update_resolve_list();
    void authorization(HttpDestination &d, HttpEvent *u);

    rpc_handler       showStats;
    async_rpc_handler postRequest;
    async_rpc_handler getRequest;
    async_rpc_handler multiRequest;
    rpc_handler       authDump;
    rpc_handler       dstDump;
    async_rpc_handler showDnsCache;
    rpc_handler       resetDnsCache;
    rpc_handler       setEventsLogLevel;

    /* true if event consumed */
    template <typename EventType> bool check_http_event_sync_ctx(const EventType &u);

    /* true if event response in multi request,
     * connection_id - sets it after finish multi request in sync_ctx_id of it
     */
    bool checkMultiResponse(const DestinationAction &action, string &connection_id);
    void sendRpcResponse(RpcRequestsMap::iterator &it, const AmArg &ret);

    bool reloadCache();

  public:
    HttpClient();
    ~HttpClient();

    static HttpClient *instance();
    static void        dispose();
    AmDynInvoke       *getInstance() { return static_cast<AmDynInvoke *>(instance()); }

    static int events_log_level;

    int onLoad();

    void run() override;
    void on_stop() override;

    void process(AmEvent *ev) override;
    void process_jsonrpc_request(JsonRpcRequestEvent &request);
    void process_http_event(AmEvent *ev);

    void on_connection_delete(CurlConnection *c) override;
    void init_rpc_tree() override;

    uint64_t get_active_tasks_count() override;
};

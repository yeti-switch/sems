#pragma once

#include <ampi/PostgreSqlAPI.h>
#include <AmApi.h>
#include <AmEventFdQueue.h>
#include <RpcTreeHandler.h>
#include "ShutdownHandler.h"
#include "ConnectionPool.h"

#include <string>
#include <map>
using std::map;
using std::string;

#define MOD_NAME "postgresql"

enum AdditionalTypeEvent { Reset = PGEvent::MaxType };

class ResetEvent : public PGEvent {
  public:
    union {
        PGWorkerPoolCreate::PoolType type;
        int                          fd;
        char                        *trans_id;
    } data;
    enum { PoolTypeReset, PoolsReset, FdReset, TransRemove } type;
    string worker_name;

    ResetEvent(const string &name, PGWorkerPoolCreate::PoolType type)
        : PGEvent(AdditionalTypeEvent::Reset)
        , type(PoolTypeReset)
        , worker_name(name)
    {
        data.type = type;
    }

    ResetEvent(const string &name, const string &trans_id)
        : PGEvent(AdditionalTypeEvent::Reset)
        , type(TransRemove)
        , worker_name(name)
    {
        data.trans_id = strdup(trans_id.c_str());
    }

    ResetEvent(const string &name)
        : PGEvent(AdditionalTypeEvent::Reset)
        , type(PoolsReset)
        , worker_name(name)
    {
        data.fd = -1;
    }

    ResetEvent(const string &name, int fd)
        : PGEvent(AdditionalTypeEvent::Reset)
        , type(FdReset)
        , worker_name(name)
    {
        data.fd = fd;
    }

    ~ResetEvent()
    {
        if (type == TransRemove)
            free(data.trans_id);
    }
};

class PostgreSQL : public AmThread,
                   public AmEventFdQueue,
                   public AmEventHandler,
                   public RpcTreeHandler,
                   public ShutdownHandler {
    friend class PostgreSQLFactory;
    static PostgreSQL *_instance;

    AmEventFd                        stop_event;
    AmCondition<bool>                stopped;
    map<string, PoolWorker *>        workers;
    map<string, JsonRpcRequestEvent> rpcRequests;
    int                              epoll_fd;

    time_t log_time;
    string log_dir;
    string events_queue_name;
    bool   log_pg_events;

    int init();

    PoolWorker *getWorker(const PGQueryData &e);
    bool        checkQueryData(const PGQueryData &data);

    void onWorkerPoolCreate(const PGWorkerPoolCreate &e);
    void onSimpleExecute(const PGExecute &e);
    void onParamExecute(const PGParamExecute &e);
    void onPrepare(const PGPrepare &e);
    void onPrepareExecute(const PGPrepareExec &e);
    void onWorkerDestroy(const PGWorkerDestroy &e);
    void onWorkerConfig(const PGWorkerConfig &e);
    void onSetSearchPath(const PGSetSearchPath &e);
    void onReset(const ResetEvent &e);
    void onRpcRequestResponse(const PGResponse &e);
    void onRpcRequestError(const string &err, const string &token);

  public:
    PostgreSQL();
    ~PostgreSQL();

    static PostgreSQL *instance();
    static void        dispose();
    AmDynInvoke       *getInstance() { return static_cast<AmDynInvoke *>(instance()); }

    int onLoad();
    int configure(const string &config);
    int reconfigure(const string &config);

    void run() override;
    void on_stop() override;

    void showStats(const AmArg &params, AmArg &ret);

#ifdef TRANS_LOG_ENABLE
    void   getConnectionLog(const AmArg &params, AmArg &ret);
    string getConnectionLogPath();
#endif
    void showConfig(const AmArg &params, AmArg &ret);
    void showRetransmit(const AmArg &params, AmArg &ret);
    void logPgEventsSync(const AmArg &args, AmArg &ret);

    async_rpc_handler showStatistics;
    async_rpc_handler showConfiguration;
    async_rpc_handler showRetransmits;
    async_rpc_handler logPgEventsAsync;
    async_rpc_handler execRequest;
    rpc_handler       requestReconnect;
    rpc_handler       resetConnection;
    rpc_handler       removeTrans;
#ifdef TRANS_LOG_ENABLE
    async_rpc_handler transLog;
#endif

    void init_rpc_tree() override;

    void process(AmEvent *ev) override;
    void process_postgres_event(AmEvent *ev);
    void process_jsonrpc_request(JsonRpcRequestEvent &request);

    time_t getLogTime() { return log_time; }
    string getLogDir() { return log_dir; }
    bool   getLogPgEvents() { return log_pg_events; }

    uint64_t get_active_tasks_count() override;
};

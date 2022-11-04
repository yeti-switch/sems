#pragma once

#include <ampi/PostgreSqlAPI.h>
#include <AmApi.h>
#include <AmEventFdQueue.h>
#include <RpcTreeHandler.h>
#include "ConnectionPool.h"

#include <string>
#include <map>
using std::string;
using std::map;

#define MOD_NAME "postgresql"

enum AdditionalTypeEvent {
    Reset = PGEvent::MaxType
};

class ResetEvent : public PGEvent
{
public:
    union {
        PGWorkerPoolCreate::PoolType type;
        int fd;
    } data;
    enum {
        PoolTypeReset,
        PoolsReset,
        FdReset
    } type;
    string worker_name;

    ResetEvent(const string& name, PGWorkerPoolCreate::PoolType type)
    : worker_name(name), type(PoolTypeReset), PGEvent(AdditionalTypeEvent::Reset){
        data.type = type;
    }
    ResetEvent(const string& name)
    : worker_name(name), type(PoolsReset), PGEvent(AdditionalTypeEvent::Reset){
        data.fd = -1;
    }
    ResetEvent(const string& name, int fd)
    : worker_name(name), type(FdReset), PGEvent(AdditionalTypeEvent::Reset){
        data.fd = fd;
    }
};

class PostgreSQL
: public AmThread
, public AmEventFdQueue
, public AmEventHandler
, public RpcTreeHandler<PostgreSQL>
{
    friend class PostgreSQLFactory;
    static PostgreSQL* _instance;

    AmEventFd stop_event;
    AmCondition<bool> stopped;
    map<string, PoolWorker*> workers;
    int epoll_fd;

    time_t log_time;
    string log_dir;

    int init();

    PoolWorker* getWorker(const PGQueryData& e);
    bool checkQueryData(const PGQueryData& data);

    void onWorkerPoolCreate(const PGWorkerPoolCreate& e);
    void onSimpleExecute(const PGExecute& e);
    void onParamExecute(const PGParamExecute& e);
    void onPrepare(const PGPrepare& e);
    void onPrepareExecute(const PGPrepareExec& e);
    void onWorkerDestroy(const PGWorkerDestroy& e);
    void onWorkerConfig(const PGWorkerConfig& e);
    void onSetSearchPath(const PGSetSearchPath& e);
    void onReset(const ResetEvent& e);

  public:
    PostgreSQL();
    ~PostgreSQL();

    static PostgreSQL* instance();
    static void dispose();
    AmDynInvoke* getInstance() { return static_cast<AmDynInvoke*>(instance()); }

    int onLoad();
    int configure(const string& config);
    int reconfigure(const string& config);

    void run() override;
    void on_stop() override;

    void showStats(const AmArg& params, AmArg& ret);

#ifdef TRANS_LOG_ENABLE
    void getConnectionLog(const AmArg& params, AmArg& ret);
#endif
    void showConfig(const AmArg& params, AmArg& ret);

    async_rpc_handler showStatistics;
    async_rpc_handler showConfiguration;
    rpc_handler requestReconnect;
    rpc_handler requestReset;
#ifdef TRANS_LOG_ENABLE
    async_rpc_handler transLog;
#endif

    void init_rpc_tree() override;

    void process(AmEvent* ev) override;
    void process_postgres_event(AmEvent* ev);
    void process_jsonrpc_request(JsonRpcRequestEvent &request);

    time_t getLogTime() { return log_time; }
    string getLogDir() { return log_dir; }
};

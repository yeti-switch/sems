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

class IPGConnection;

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
    AmMutex mutex;
    map<string, Worker*> workers;
    int epoll_fd;

    int init();

    Worker* getWorker(const PGQueryData& e);

    void onWorkerPoolCreate(const PGWorkerPoolCreate& e);
    void onSimpleExecute(const PGExecute& e);
    void onParamExecute(const PGParamExecute& e);
    void onPrepare(const PGPrepare& e);
    void onPrepareExecute(const PGPrepareExec& e);
    void onWorkerDestroy(const PGWorkerDestroy& e);
    void onWorkerConfig(const PGWorkerConfig& e);
    void onSetSearchPath(const PGSetSearchPath& e);

  public:
    PostgreSQL();
    ~PostgreSQL();

    static PostgreSQL* instance();
    static void dispose();
    AmDynInvoke* getInstance() { return static_cast<AmDynInvoke*>(instance()); }

    int onLoad();

    void run() override;
    void on_stop() override;

    rpc_handler showStats;

    void init_rpc_tree() override;

    void process(AmEvent* ev) override;
    void process_postgres_event(AmEvent* ev);
};

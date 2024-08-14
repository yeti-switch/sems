#pragma once

#include <ampi/PostgreSqlAPI.h>
#include <AmApi.h>
#include <AmEventFdQueue.h>
#include <RpcTreeHandler.h>

#include <string>
#include <vector>
#include <map>
using std::string;
using std::vector;
using std::map;

class PostgreSqlMock
  : public AmThread,
    public AmEventFdQueue,
    public AmEventHandler,
    public RpcTreeHandler<PostgreSqlMock>
{
    friend class PostgreSqlMockFactory;
    static PostgreSqlMock* _instance;

    AmEventFd stop_event;
    AmCondition<bool> stopped;
    int epoll_fd;

    int init();
    bool checkQueryData(const PGQueryData& data);
    string find_resp_for_query(const string& query);
    void handle_query(const string& query, const string& sender_id, const string& token);
    void handle_query_data(const PGQueryData& qdata);
    void onSimpleExecute(const PGExecute& e);
    void onParamExecute(const PGParamExecute& e);
    void onPrepareExecute(const PGPrepareExec& e);

    vector<string> resp_stack;
    map<string, string> resp_map;

  protected:
    rpc_handler stackPush;
    rpc_handler stackClear;
    rpc_handler stackShow;
    rpc_handler mapInsert;
    rpc_handler mapClear;
    rpc_handler mapShow;

    void init_rpc_tree() override;
    void on_stop() override;
    void run() override;
    void process(AmEvent* ev) override;
    void process_postgres_event(AmEvent* ev);

  public:
    PostgreSqlMock();
    ~PostgreSqlMock();

    static PostgreSqlMock* instance();
    static void dispose();
    AmDynInvoke* getInstance() { return static_cast<AmDynInvoke*>(instance()); }

    int onLoad();
    int configure(const string& config);
    int reconfigure(const string& config);
};

#pragma once

#include <ampi/PostgreSqlAPI.h>
#include <AmApi.h>
#include <AmEventFdQueue.h>
#include <RpcTreeHandler.h>

#include <lua.hpp>

#include <string>
#include <vector>
#include <map>
#include <memory>
using std::string;
using std::vector;
using std::map;
using std::unique_ptr;

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

    struct Response {
        int ref_index;
        string value;
        AmArg parsed_value;
        string error;
        bool timeout;
    };

    int init();
    bool checkQueryData(const PGQueryData& data);
    Response* find_resp_for_query(const string& query);
    void handle_query(const string& query, const string& sender_id, const string& token, const vector<AmArg>& params);
    void handle_query_data(const PGQueryData& qdata);
    void onSimpleExecute(const PGExecute& e);
    void onParamExecute(const PGParamExecute& e);
    void onPrepareExecute(const PGPrepareExec& e);

    vector<unique_ptr<Response>> resp_stack;
    map<string, unique_ptr<Response>> resp_map;
    lua_State* state;

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

    int insert_resp_map(const string& query, const string& resp, const string& error = string(), bool timeout = false);
    int insert_resp_lua(const string& query, const string& path);
};

#pragma once

#include <ampi/PostgreSqlAPI.h>
#include <AmApi.h>
#include <AmEventFdQueue.h>
#include <RpcTreeHandler.h>

#include <lua.hpp>

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
using std::string;
using std::vector;
using std::map;
using std::unique_ptr;

class PostgreSqlProxy
  : public AmThread,
    public AmEventFdQueue,
    public AmEventHandler,
    public RpcTreeHandler<PostgreSqlProxy>
{
    friend class PostgreSqlMockFactory;
    static PostgreSqlProxy* _instance;

    AmEventFd stop_event;
    AmCondition<bool> stopped;
    int epoll_fd;

    struct Response {
        int ref_index;

        string upstream_queue;

        string value;
        AmArg parsed_value;
        string error;
        bool timeout;
    };

    int init();
    bool checkQueryData(const PGQueryData& data);
    Response* find_resp_for_query(const string& query);
    std::optional<string> handle_query(const string& query, const string& sender_id, const string& token, const vector<AmArg>& params);
    std::optional<string> handle_query_data(const PGQueryData& qdata);
    std::optional<string> onSimpleExecute(const PGExecute& e);
    std::optional<string> onParamExecute(const PGParamExecute& e);
    std::optional<string> onPrepareExecute(const PGPrepareExec& e);
    std::optional<string> onCfgWorkerManagementEvent(const string &worker_name);

    vector<unique_ptr<Response>> resp_stack;
    std::unordered_map<string, unique_ptr<Response>> resp_map;
    std::unordered_map<string, string> upstream_workers;
    lua_State* state;
    string module_config;

    void insert_response(const string& query, std::unique_ptr<Response> &response);

  protected:
    async_rpc_handler stackPush;
    async_rpc_handler stackClear;
    async_rpc_handler stackShow;
    async_rpc_handler mapInsert;
    async_rpc_handler mapClear;
    async_rpc_handler mapShow;
    async_rpc_handler reload;
    void reloadMap(const AmArg& args, AmArg& ret);
    void pushStack(const AmArg& args, AmArg& ret);
    void clearStack(const AmArg& args, AmArg& ret);
    void showStack(const AmArg& args, AmArg& ret);
    void insertMap(const AmArg& args, AmArg& ret);
    void clearMap(const AmArg& args, AmArg& ret);
    void showMap(const AmArg& args, AmArg& ret);

    void init_rpc_tree() override;
    void on_stop() override;
    void run() override;
    void process(AmEvent* ev) override;
    bool process_consuming(AmEvent* ev) override;
    bool process_postgres_event(PGEvent* ev);
    void process_jsonrpc_event(JsonRpcRequestEvent* ev);

  public:
    PostgreSqlProxy();
    ~PostgreSqlProxy();

    static PostgreSqlProxy* instance();
    static void dispose();
    AmDynInvoke* getInstance() { return static_cast<AmDynInvoke*>(instance()); }

    int onLoad();
    int configure(const string& config);
    int reconfigure(const string& config);

    int insert_resp_map(const string& query, const string& resp, const string& error = string(), bool timeout = false);
    int insert_resp_lua(const string& query, const string& path);
    int insert_upstream_mapping(const string& query, const string &queue);
    int insert_upstream_worker_mapping(const string& worker, const string &queue);
};

#include "PostgreSqlProxy.h"
#include "log.h"
#include "AmEventDispatcher.h"
#include "Config.h"
#include "pg_log.h"
#include "format_helper.h"

#include <jsonArg.h>
#include <math.h>

#define eventDispatcher  AmEventDispatcher::instance()
#define sessionContainer AmSessionContainer::instance()

#define EPOLL_MAX_EVENTS 2048

class PostgreSqlProxyFactory : public AmDynInvokeFactory, public AmConfigFactory {
    PostgreSqlProxyFactory(const string &name)
        : AmDynInvokeFactory(name)
        , AmConfigFactory(name)
    {
        PostgreSqlProxy::instance();
    }
    ~PostgreSqlProxyFactory() { PostgreSqlProxy::dispose(); }

  public:
    DECLARE_FACTORY_INSTANCE(PostgreSqlProxyFactory);

    AmDynInvoke *getInstance() { return PostgreSqlProxy::instance(); }

    int onLoad() { return PostgreSqlProxy::instance()->onLoad(); }

    void on_destroy() { PostgreSqlProxy::instance()->stop(); }

    int configure(const string &config) { return PostgreSqlProxy::instance()->configure(config); }

    int reconfigure(const string &config) { return PostgreSqlProxy::instance()->reconfigure(config); }
};

EXPORT_PLUGIN_CLASS_FACTORY(PostgreSqlProxyFactory);
EXPORT_PLUGIN_CONF_FACTORY(PostgreSqlProxyFactory);
DEFINE_FACTORY_INSTANCE(PostgreSqlProxyFactory, MOD_NAME);

enum RpcMethodId {
    MethodReload,
    MethodStackPush,
    MethodStackClear,
    MethodStackShow,
    MethodMapInsert,
    MethodMapClear,
    MethodMapShow,
    MethodShowStats,
    MethodLogPgEvents
};

PostgreSqlProxy *PostgreSqlProxy::_instance = 0;

PostgreSqlProxy *PostgreSqlProxy::instance()
{
    if (_instance == nullptr)
        _instance = new PostgreSqlProxy();

    return _instance;
}


void PostgreSqlProxy::dispose()
{
    if (_instance != nullptr) {
        delete _instance;
        _instance = nullptr;
    }
}

PostgreSqlProxy::PostgreSqlProxy()
    : AmEventFdQueue(this)
{
    eventDispatcher->addEventQueue(POSTGRESQL_QUEUE, this);
    state = luaL_newstate();
    luaL_openlibs(state);
    lua_pushlightuserdata(state, state);
    lua_setglobal(state, "pgtimeout");
}

PostgreSqlProxy::~PostgreSqlProxy()
{
    eventDispatcher->delEventQueue(POSTGRESQL_QUEUE);
    lua_close(state);
}

int PostgreSqlProxy::onLoad()
{
    if (init()) {
        ERROR("initialization error");
        return -1;
    }

    start();
    return 0;
}

int PostgreSqlProxy::configure(const string &config)
{
    cfg_t *cfg = cfg_init(pg_opts, CFGF_NONE);
    if (!cfg)
        return -1;

    switch (cfg_parse_buf(cfg, config.c_str())) {
    case CFG_SUCCESS: break;
    case CFG_PARSE_ERROR:
        ERROR("configuration of module %s parse error", MOD_NAME);
        cfg_free(cfg);
        return -1;
    default:
        ERROR("unexpected error on configuration of module %s processing", MOD_NAME);
        cfg_free(cfg);
        return -1;
    }

    log_pg_events = cfg_getbool(cfg, CFG_OPT_LOG_PG_EVENTS_NAME);
    module_config = config;
    if (cfg_size(cfg, CFG_OPT_UPSTREAM_QUEUE))
        upstream_queue = cfg_getstr(cfg, CFG_OPT_UPSTREAM_QUEUE);
    cfg_free(cfg);
    return 0;
}

int PostgreSqlProxy::reconfigure(const string &config)
{
    return configure(config);
}

int PostgreSqlProxy::init()
{
    if ((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    epoll_link(epoll_fd, true);
    stop_event.link(epoll_fd, true);
    init_rpc();

    DBG("PostgreSqlProxy Client initialized");
    return 0;
}

/* AmThread */

void PostgreSqlProxy::run()
{
    void              *p;
    bool               running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    setThreadName("pg-client-proxy");

    running = true;
    do {
        int ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if (ret == -1 && errno != EINTR) {
            ERROR("epoll_wait: %s", strerror(errno));
        }

        if (ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            p                     = e.data.ptr;

            if (p == static_cast<AmEventFdQueue *>(this)) {
                processEvents();
            } else if (p == &stop_event) {
                stop_event.read();
                running = false;
                break;
            }
        }
    } while (running);

    epoll_unlink(epoll_fd);
    close(epoll_fd);

    DBG("PostgreSqlProxy Client stopped");
}

void PostgreSqlProxy::on_stop()
{
    stop_event.fire();
    join();
}

/* rpc handlers */

bool PostgreSqlProxy::stackPush(const string &connection_id, const AmArg &request_id, const AmArg &params)
{
    postEvent(new JsonRpcRequestEvent(connection_id, request_id, false, MethodStackPush, params));
    return true;
}

bool PostgreSqlProxy::stackClear(const string &connection_id, const AmArg &request_id, const AmArg &params)
{
    postEvent(new JsonRpcRequestEvent(connection_id, request_id, false, MethodStackClear, params));
    return true;
}

bool PostgreSqlProxy::stackShow(const string &connection_id, const AmArg &request_id, const AmArg &params)
{
    postEvent(new JsonRpcRequestEvent(connection_id, request_id, false, MethodStackShow, params));
    return true;
}

bool PostgreSqlProxy::reload(const string &connection_id, const AmArg &request_id, const AmArg &params)
{
    postEvent(new JsonRpcRequestEvent(connection_id, request_id, false, MethodReload, params));
    return true;
}

bool PostgreSqlProxy::logPgEventsAsync(const string &connection_id, const AmArg &request_id, const AmArg &params)
{
    postEvent(new JsonRpcRequestEvent(connection_id, request_id, false, MethodLogPgEvents, params));
    return true;
}

bool PostgreSqlProxy::mapClear(const string &connection_id, const AmArg &request_id, const AmArg &params)
{
    postEvent(new JsonRpcRequestEvent(connection_id, request_id, false, MethodMapClear, params));
    return true;
}

bool PostgreSqlProxy::mapInsert(const string &connection_id, const AmArg &request_id, const AmArg &params)
{
    postEvent(new JsonRpcRequestEvent(connection_id, request_id, false, MethodMapInsert, params));
    return true;
}

bool PostgreSqlProxy::mapShow(const string &connection_id, const AmArg &request_id, const AmArg &params)
{
    postEvent(new JsonRpcRequestEvent(connection_id, request_id, false, MethodMapShow, params));
    return true;
}

bool PostgreSqlProxy::showStatsAsync(const string &connection_id, const AmArg &request_id, const AmArg &params)
{
    postEvent(new JsonRpcRequestEvent(connection_id, request_id, false, MethodShowStats, params));
    return true;
}

void PostgreSqlProxy::pushStack(const AmArg &args, AmArg &)
{
    if (args.size() == 0)
        return;

    auto response       = new Response();
    response->ref_index = 0;
    response->value     = arg2str(args[0]);
    if (args.size() > 1)
        response->error = arg2str(args[1]);
    if (args.size() > 2)
        response->timeout = (arg2str(args[2]) == "true");
    resp_stack.emplace_back(response);
}

void PostgreSqlProxy::clearStack(const AmArg &, AmArg &)
{
    resp_stack.clear();
}

void PostgreSqlProxy::showStack(const AmArg &args, AmArg &ret)
{
    for (auto &it : resp_stack) {
        ret.push(AmArg());
        AmArg &r = ret.back();
        r.push(AmArg(it->value));
        r.push(AmArg(it->error));
        r.push(AmArg(it->timeout));
    }
}

void PostgreSqlProxy::insertMap(const AmArg &args, AmArg &ret)
{
    string                    query;
    vector<AmArg>             params;
    std::unique_ptr<Response> response{ new Response() };
    if (isArgArray(args)) {
        if (args.size() == 0)
            return;

        query               = arg2str(args[0]);
        response->ref_index = 0;
        if (args.size() > 1)
            response->parsed_value = args[1];
        if (args.size() > 2)
            response->error = arg2str(args[2]);
        if (args.size() > 3) {
            bool new_value;
            if (!str2bool(arg2str(args[3]), new_value)) {
                ret = format("failed to convert '{}' to bool", arg2str(args[3]));
                return;
            }

            response->timeout = new_value;
        }
    } else if (isArgStruct(args)) {
        if (!args.hasMember("query") || !args.hasMember("response")) {
            ret = format("incorrect arguments of commands");
            return;
        }
        if (args.hasMember("params") && !isArgArray(args["params"])) {
            ret = format("incorrect arguments of commands");
            return;
        }
        query = arg2str(args["query"]);
        if (args.hasMember("params")) {
            for (int i = 0; i < args["params"].size(); i++)
                params.push_back(args["params"][i]);
        }
        if (args["response"].hasMember("error"))
            response->error = arg2str(args["response"]["error"]);
        if (args["response"].hasMember("value"))
            response->parsed_value = args["response"]["value"];
        if (args["response"].hasMember("timeout")) {
            if (!isArgBool(args["response"]["timeout"])) {
                ret = format("incorrect type of timeout value in repsponse");
                return;
            }

            response->timeout = args["response"]["timeout"].asBool();
        }
    }
    insert_response(query, params, response);
}

void PostgreSqlProxy::clearMap(const AmArg &, AmArg &)
{
    resp_map.clear();
}

void PostgreSqlProxy::showMap(const AmArg &, AmArg &ret)
{
    ret.assertArray();
    for (auto &[query, resp] : resp_map) {
        ret.push({
            {     "query",        query.query },
            { "ref_index",    resp->ref_index },
            {     "value", resp->parsed_value },
            {     "error",        resp->error },
            {   "timeout",      resp->timeout }
        });
        for (auto &param : query.params)
            ret.back()["params"].push(param);
    }
}

void PostgreSqlProxy::showStatsSync(const AmArg &, AmArg &ret)
{
    size_t queue_size;
    {
        AmLock l(m_queue);
        queue_size = ev_queue.size();
    };

    ret = AmArg{
        { "queue_size", queue_size }
    };
}

void PostgreSqlProxy::logPgEventsSync(const AmArg &args, AmArg &ret)
{
    if (args.size() != 1) {
        ret = "argument expected";
        return;
    }

    bool new_value;
    if (!str2bool(arg2str(args[0]), new_value)) {
        ret = format("failed to convert '{}' to bool", arg2str(args[0]));
        return;
    }

    log_pg_events = new_value;

    ret = AmArg{
        { "log_pg_events", log_pg_events }
    };
}

void PostgreSqlProxy::reloadMap(const AmArg &, AmArg &)
{
    reconfigure(module_config);
}

/* RpcTreeHandler */

void PostgreSqlProxy::init_rpc_tree()
{
    reg_method(root, "reload", "reload all maps", "", &PostgreSqlProxy::reload, this);
    auto &stack = reg_leaf(root, "stack");
    reg_method(stack, "push", "stack push", "", &PostgreSqlProxy::stackPush, this);
    reg_method(stack, "clear", "stack clear", "", &PostgreSqlProxy::stackClear, this);
    reg_method(stack, "show", "stack show", "", &PostgreSqlProxy::stackShow, this);
    auto &map = reg_leaf(root, "map");
    reg_method(map, "insert", "map insert", "", &PostgreSqlProxy::mapInsert, this);
    reg_method(map, "clear", "map clear", "", &PostgreSqlProxy::mapClear, this);
    reg_method(map, "show", "map show", "", &PostgreSqlProxy::mapShow, this);

    auto &show = reg_leaf(root, "show");
    reg_method(show, "stats", "show module stats", "", &PostgreSqlProxy::showStatsAsync, this);

    auto &set = reg_leaf(root, "set");
    reg_method(set, "logPgEvents", "enable/disable pg events logs", "", &PostgreSqlProxy::logPgEventsAsync, this);
}

/* AmEventHandler */

void PostgreSqlProxy::process(AmEvent *) {}
bool PostgreSqlProxy::process_consuming(AmEvent *ev)
{
    switch (ev->event_id) {
    case E_SYSTEM:
    {
        if (AmSystemEvent *sys_ev = dynamic_cast<AmSystemEvent *>(ev)) {
            switch (sys_ev->sys_event) {
            case AmSystemEvent::ServerShutdown: stop_event.fire(); break;
            default:                            break;
            }
        }
    } break;
    default:
        if (PGEvent *pgev = dynamic_cast<PGEvent *>(ev))
            return process_postgres_event(pgev);
        else if (JsonRpcRequestEvent *jsonprc = dynamic_cast<JsonRpcRequestEvent *>(ev))
            process_jsonrpc_event(jsonprc);
    }

    return false;
}

bool PostgreSqlProxy::process_postgres_event(PGEvent *ev)
{
    std::optional<string> ret;

    if (log_pg_events)
        DBG(pg_log::print_pg_event(ev).c_str());

    switch (ev->event_id) {
    case PGEvent::SimpleExecute:
        if (PGExecute *e = dynamic_cast<PGExecute *>(ev))
            ret = onSimpleExecute(*e);
        break;
    case PGEvent::ParamExecute:
        if (PGParamExecute *e = dynamic_cast<PGParamExecute *>(ev))
            ret = onParamExecute(*e);
        break;
    case PGEvent::Prepare:
        if (PGPrepare *e = dynamic_cast<PGPrepare *>(ev))
            ret = onCfgWorkerManagementEvent(e->worker_name);
        break;
    case PGEvent::PrepareExec:
        if (PGPrepareExec *e = dynamic_cast<PGPrepareExec *>(ev))
            ret = onPrepareExecute(*e);
        break;
    case PGEvent::WorkerPoolCreate:
        if (auto *e = dynamic_cast<PGWorkerPoolCreate *>(ev))
            ret = onCfgWorkerManagementEvent(e->worker_name);
        break;
    case PGEvent::WorkerConfig:
        if (auto *e = dynamic_cast<PGWorkerConfig *>(ev))
            ret = onCfgWorkerManagementEvent(e->worker_name);
        break;
    case PGEvent::WorkerDestroy:
        if (auto *e = dynamic_cast<PGWorkerDestroy *>(ev))
            ret = onCfgWorkerManagementEvent(e->worker_name);
        break;
    case PGEvent::SetSearchPath:
        if (auto *e = dynamic_cast<PGSetSearchPath *>(ev))
            ret = onCfgWorkerManagementEvent(e->worker_name);
        break;
    }

    if (ret) {
        if (eventDispatcher->post(ret.value(), ev)) {
            return true;
        }
        return false;
    }

    return false;
}

void PostgreSqlProxy::process_jsonrpc_event(JsonRpcRequestEvent *ev)
{
    AmArg ret;
    switch (ev->method_id) {
    case MethodReload:      reloadMap(ev->params, ret); break;
    case MethodStackPush:   pushStack(ev->params, ret); break;
    case MethodStackClear:  clearStack(ev->params, ret); break;
    case MethodStackShow:   showStack(ev->params, ret); break;
    case MethodMapClear:    clearMap(ev->params, ret); break;
    case MethodMapInsert:   insertMap(ev->params, ret); break;
    case MethodMapShow:     showMap(ev->params, ret); break;
    case MethodShowStats:   showStatsSync(ev->params, ret); break;
    case MethodLogPgEvents: logPgEventsSync(ev->params, ret); break;
    }

    postJsonRpcReply(*ev, ret);
}

bool PostgreSqlProxy::checkQueryData(const PGQueryData &data)
{
    if (data.info.empty()) {
        auto *ev = new PGResponseError("absent query", data.token);

        if (log_pg_events)
            DBG(pg_log::print_pg_event(ev).c_str());

        sessionContainer->postEvent(data.sender_id, ev);
        return false;
    }

    return true;
}

PostgreSqlProxy::Response *PostgreSqlProxy::find_resp_for_query(const string &query, const vector<AmArg> &params)
{
    auto resp_it1 = resp_map.find(Query(query, params));
    auto resp_it2 = resp_map.find(Query(query, vector<AmArg>()));
    if (resp_it1 == resp_map.end() && resp_it2 == resp_map.end()) {
        if (resp_stack.empty())
            return nullptr;

        auto resp = resp_stack.back().release();
        resp_stack.pop_back();
        return resp;
    }

    return resp_it1 == resp_map.end() ? resp_it2->second.get() : resp_it1->second.get();
}

static inline bool lua_isnumeric(lua_State *state, int index)
{
    return lua_type(state, index) == LUA_TNUMBER;
}

static inline bool is_index(const char *name)
{
    char *endptr = NULL;
    long  l_i    = strtol(name, &endptr, 10);
    return endptr && *endptr == '\0' && l_i;
}

void response2AmArg(lua_State *state, AmArg &arg)
{
    if (lua_isnumeric(state, -1)) {
        double number = lua_tonumber(state, -1);
        if (floor(number) == number)
            arg = (int)floor(number);
        else
            arg = number;
    } else if (lua_isstring(state, -1))
        arg = lua_tostring(state, -1);
    else if (lua_isboolean(state, -1))
        arg = (lua_toboolean(state, -1) == 1);
    else if (lua_istable(state, -1)) {
        lua_pushnil(state);
        while (lua_next(state, -2) != 0) {
            lua_pushvalue(state, -2);
            AmArg *value;
            if (is_index(lua_tostring(state, -1))) {
                int index;
                str2int(lua_tostring(state, -1), index);
                value = &arg[index - 1];
            } else {
                value = &arg[lua_tostring(state, -1)];
            }
            lua_pushvalue(state, -2);
            response2AmArg(state, *value);
            lua_pop(state, 3);
        }
    }
}

[[maybe_unused]] static void push_query_param(lua_State *L, AmArg &param)
{
    // see: apps/postgresql/query/QueryParam.cpp: getParams(const std::vector<AmArg>& params)
    if (isArgUndef(param))
        lua_pushnil(L);
    else if (isArgInt(param))
        lua_pushinteger(L, param.asInt());
    else if (isArgLongLong(param))
        lua_pushinteger(L, param.asLongLong());
    else if (isArgCStr(param))
        lua_pushstring(L, param.asCStr());
    else if (isArgDouble(param))
        lua_pushnumber(L, param.asDouble());
    else if (isArgArray(param)) {
        // TODO: create lua table here
        lua_pushstring(L, arg2json(param).data());
    } else if (isArgBool(param))
        lua_pushboolean(L, param.asBool());
    else if (isArgStruct(param)) {
        if (param.hasMember("pg")) {
            AmArg &a = param["pg"];
            if (isArgArray(a) && a.size() == 2 && isArgCStr(a[0])) {
                // TODO: mimic QueryParam::QueryParam(unsigned int param_oid, const AmArg &val)
                // recursive serialization to the lua table ?
                lua_pushstring(L, arg2json(a[1]).data());
            } else {
                ERROR("unexpected format in typed param: %s. add as json", AmArg::print(param).data());
                lua_pushstring(L, arg2json(a[1]).data());
            }
        } else {
            lua_pushstring(L, arg2json(param).data());
        }
    } else {
        WARN("unsupported AmArg type: %s. replace with nil", param.getTypeStr());
        lua_pushnil(L);
    }
}

std::optional<string> PostgreSqlProxy::handle_query(const string &query, const string &sender_id, const string &token,
                                                    const vector<AmArg> &params)
{
    static string no_mapped_error{ "no mapping" };

    const auto response = find_resp_for_query(query, params);
    if (!response && upstream_queue.empty()) {
        ERROR("no mapping for the query: <%s>", query.data());
        auto *ev = new PGResponseError(no_mapped_error, token);

        if (log_pg_events)
            DBG(pg_log::print_pg_event(ev).c_str());

        sessionContainer->postEvent(sender_id, ev);
        return std::nullopt;
    } else if (!response)
        return upstream_queue;

    if (response->ref_index) {
        response->timeout = false;
        response->error.clear();
        response->parsed_value.clear();
        response->value.clear();

        if (!lua_checkstack(state, params.size() + 2)) {
            auto *ev = new PGResponseError("failed to ensure lua stacksize", token);

            if (log_pg_events)
                DBG(pg_log::print_pg_event(ev).c_str());

            sessionContainer->postEvent(sender_id, ev);
            return std::nullopt;
        }

        lua_rawgeti(state, LUA_REGISTRYINDEX, response->ref_index);
        lua_pushstring(state, query.c_str());
        for (auto param : params)
            push_query_param(state, param);

        int ret = lua_pcall(state, params.size() + 1, 1, 0);

        if (ret) {
            response->error = lua_tostring(state, -1);
        } else if (lua_isuserdata(state, -1)) {
            if (lua_touserdata(state, -1) == state)
                response->timeout = true;
            else {
                response->error = "unknown userdata returned by function";
            }
        } else {
            response2AmArg(state, response->parsed_value);
        }

        lua_gc(state, LUA_GCCOLLECT, 0);
        lua_pop(state, lua_gettop(state));

    } else if (!response->upstream_queue.empty()) {
        return response->upstream_queue;
    }

    if (!response->error.empty()) {
        auto *ev = new PGResponseError(response->error, token);

        if (log_pg_events)
            DBG(pg_log::print_pg_event(ev).c_str());

        sessionContainer->postEvent(sender_id, ev);
        return std::nullopt;
    }

    if (response->timeout) {
        auto *ev = new PGTimeout(token);

        if (log_pg_events)
            DBG(pg_log::print_pg_event(ev).c_str());

        sessionContainer->postEvent(sender_id, ev);
        return std::nullopt;
    }

    auto *ev = new PGResponse(response->parsed_value, token);

    if (log_pg_events)
        DBG(pg_log::print_pg_event(ev).c_str());

    sessionContainer->postEvent(sender_id, ev);

    return std::nullopt;
}

std::optional<string> PostgreSqlProxy::handle_query_data(const PGQueryData &qdata)
{
    for (auto qinfo : qdata.info) {
        // assume that combined events always use the same mapping
        auto ret = handle_query(qinfo.query, qdata.sender_id, qdata.token, qinfo.params);
        if (ret)
            return ret;
    }
    return std::nullopt;
}

std::optional<string> PostgreSqlProxy::onSimpleExecute(const PGExecute &e)
{
    if (!checkQueryData(e.qdata))
        return std::nullopt;
    return handle_query_data(e.qdata);
}

std::optional<string> PostgreSqlProxy::onParamExecute(const PGParamExecute &e)
{
    if (!checkQueryData(e.qdata))
        return std::nullopt;
    return handle_query_data(e.qdata);
}

std::optional<string> PostgreSqlProxy::onPrepareExecute(const PGPrepareExec &e)
{
    vector<AmArg> params;
    return handle_query(e.info.query, e.sender_id, e.token, params);
}

std::optional<string> PostgreSqlProxy::onCfgWorkerManagementEvent(const string &worker_name)
{
    if (auto it = upstream_workers.find(worker_name); it != upstream_workers.end()) {
        return it->second;
    }
    return std::nullopt;
}

void PostgreSqlProxy::insert_response(const string &query, const vector<AmArg> &params,
                                      std::unique_ptr<Response> &response)
{
    if (auto resp_it = resp_map.find(Query(query, params)); resp_it != resp_map.end()) {
        if (resp_it->second->ref_index)
            luaL_unref(state, LUA_REGISTRYINDEX, resp_it->second->ref_index);
        resp_it->second.reset(response.release());
    } else
        resp_map.emplace(Query(query, params), response.release());
}

int PostgreSqlProxy::insert_resp_map(const string &query, const string &resp, const string &error, bool timeout)
{
    /*DBG("query [%s]: \n\t - value: %s \n\t - error: %s \n\t - timeout: %d",
        query.c_str(), resp.c_str(), error.c_str(), timeout);*/

    std::unique_ptr<Response> response{ new Response() };

    response->value     = resp;
    response->ref_index = 0;
    response->error     = error;
    response->timeout   = timeout;

    if (!json2arg(response->value, response->parsed_value)) {
        DBG("json2arg failed for value '%s'", response->value.c_str());
        return 1;
    }

    insert_response(query, vector<AmArg>() /*params*/, response);

    return 0;
}

int PostgreSqlProxy::insert_resp_lua(const string &query, const string &path)
{
    if (luaL_loadfile(state, path.c_str())) {
        ERROR("error lua script: `%s`", lua_isstring(state, -1) ? lua_tostring(state, -1) : "");
        return 1;
    }
    int ret = lua_pcall(state, 0, 1, 0);
    if (ret) {
        ERROR("lua script abort: `%s`", lua_isstring(state, -1) ? lua_tostring(state, -1) : "");
        return 1;
    } else if (!lua_isfunction(state, -1)) {
        ERROR("lua script `%s` has to return function", path.c_str());
        return 1;
    }

    std::unique_ptr<Response> response{ new Response() };
    response->ref_index = luaL_ref(state, LUA_REGISTRYINDEX);
    response->timeout   = false;

    lua_gc(state, LUA_GCCOLLECT, 0);
    lua_pop(state, lua_gettop(state));

    insert_response(query, vector<AmArg>() /*params*/, response);

    return 0;
}

int PostgreSqlProxy::insert_upstream_mapping(const string &query, const string &queue)
{
    std::unique_ptr<Response> response{ new Response() };

    response->upstream_queue = queue;
    response->ref_index      = 0;
    response->timeout        = false;

    insert_response(query, vector<AmArg>() /*params*/, response);

    return 0;
}

int PostgreSqlProxy::insert_upstream_worker_mapping(const string &worker, const string &queue)
{
    upstream_workers.emplace(worker, queue);
    return 0;
}

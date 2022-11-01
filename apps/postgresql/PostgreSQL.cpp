#include "PostgreSQL.h"

#include "log.h"
#include "AmEventDispatcher.h"

#include <vector>
#include "PolicyFactory.h"
#include "Connection.h"
#include "postgresql_cfg.h"
using std::vector;

#define EPOLL_MAX_EVENTS    2048

enum RpcMethodId {
    MethodShowStats,
    MethodShowConfig,
    MethodTransLog
};

class PostgreSQLFactory
  : public AmDynInvokeFactory
  , public AmConfigFactory
{
    PostgreSQLFactory(const string& name)
      : AmDynInvokeFactory(name)
      , AmConfigFactory(name)
    {
        PostgreSQL::instance();
    }
    ~PostgreSQLFactory()
    {
        INFO("~PostgreSQLFactory");
        PostgreSQL::dispose();
    }
  public:
    DECLARE_FACTORY_INSTANCE(PostgreSQLFactory);

    AmDynInvoke* getInstance() {
        return PostgreSQL::instance();
    }
    int onLoad() {
        return PostgreSQL::instance()->onLoad();
    }
    void on_destroy() {
        PostgreSQL::instance()->stop();
    }

    int configure(const std::string& config) {
        return PostgreSQL::instance()->configure(config);
    }

    int reconfigure(const std::string& config) {
        return PostgreSQL::instance()->reconfigure(config);
    }
};

EXPORT_PLUGIN_CLASS_FACTORY(PostgreSQLFactory);
DEFINE_FACTORY_INSTANCE(PostgreSQLFactory, MOD_NAME);

PostgreSQL* PostgreSQL::_instance=0;

PostgreSQL* PostgreSQL::instance()
{
    if(_instance == nullptr){
        _instance = new PostgreSQL();
    }
    return _instance;
}


void PostgreSQL::dispose()
{
    if(_instance != nullptr){
        delete _instance;
    }
    _instance = nullptr;
}

PostgreSQL::PostgreSQL()
: AmEventFdQueue(this)
{
    AmEventDispatcher::instance()->addEventQueue(POSTGRESQL_QUEUE, this);
}

PostgreSQL::~PostgreSQL()
{
    AmEventDispatcher::instance()->delEventQueue(POSTGRESQL_QUEUE);
}

int PostgreSQL::onLoad()
{
    if(init()){
        ERROR("initialization error");
        return -1;
    }
    start();
    return 0;
}

void cfg_error_callback(cfg_t *cfg, const char *fmt, va_list ap)
{
    char buf[2048];
    char *s = buf;
    char *e = s+sizeof(buf);

    if(cfg->title) {
        s += snprintf(s,e-s, "%s:%d [%s/%s]: ",
            cfg->filename,cfg->line,cfg->name,cfg->title);
    } else {
        s += snprintf(s,e-s, "%s:%d [%s]: ",
            cfg->filename,cfg->line,cfg->name);
    }
    s += vsnprintf(s,e-s,fmt,ap);

    ERROR("%.*s",(int)(s-buf),buf);
}

int PostgreSQL::configure(const std::string& config)
{
    cfg_t *cfg = cfg_init(pg_opt, CFGF_NONE);
    if(!cfg) return -1;

    switch(cfg_parse_buf(cfg, config.c_str())) {
    case CFG_SUCCESS:
        break;
    case CFG_PARSE_ERROR:
        ERROR("configuration of module %s parse error",MOD_NAME);
        cfg_free(cfg);
        return -1;
    default:
        ERROR("unexpected error on configuration of module %s processing",MOD_NAME);
        cfg_free(cfg);
        return -1;
    }

    log_time = cfg_getint(cfg, PARAM_LOG_TIME_NAME);
    log_dir = cfg_getstr(cfg, PARAM_LOG_DIR_NAME);

    cfg_free(cfg);
    return 0;
}

int PostgreSQL::reconfigure(const std::string& config)
{
    return configure(config);
}

int PostgreSQL::init()
{
    if((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    epoll_link(epoll_fd, true);
    stop_event.link(epoll_fd,true);

    makePolicyFactory(false);
    init_rpc();

    DBG("PostgreSQL Client initialized");
    return 0;
}

void PostgreSQL::run()
{
    void *p;
    bool running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    setThreadName("pg-client");

    running = true;
    do {
        int ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if(ret == -1 && errno != EINTR){
            ERROR("epoll_wait: %s",strerror(errno));
        }

        if(ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            p = e.data.ptr;

            if(p==static_cast<AmEventFdQueue *>(this)){
                processEvents();
            } else if(p==&stop_event){
                stop_event.read();
                running = false;
                break;
            } else {
                bool is_connection = true;
                for(auto& worker : workers) {
                    if(worker.second->processEvent(p)) {
                        is_connection = false;
                        break;
                    }
                }
                if(is_connection) {
                    IPGConnection* conn = (IPGConnection*)e.data.ptr;
                    conn->check();
                }
            }
        }
    } while(running);

    {
        for(auto& worker : workers) delete worker.second;
        workers.clear();
    }

    epoll_unlink(epoll_fd);
    close(epoll_fd);

    DBG("PostgreSQL Client stopped");

    stopped.set(true);
}

void PostgreSQL::on_stop()
{
    stop_event.fire();
    stopped.wait_for();
}

bool PostgreSQL::showStatistics(const string& connection_id,
                           const AmArg& request_id,
                           const AmArg& params)
{
    postEvent(new JsonRpcRequestEvent(
        connection_id, request_id, false,
        MethodShowStats, params));
    return true;
}

void PostgreSQL::showStats(const AmArg&, AmArg& ret)
{
    AmArg& wrs_arr = ret["workers"];
    for(auto& dest : workers) {
        AmArg& worker = wrs_arr[dest.first.c_str()];
        dest.second->getStats(worker);
    }
}

void PostgreSQL::getConnectionLog(const AmArg& params, AmArg& ret)
{
    bool res = false;
    //AmArg& wrs_arr = ret["workers"];
    for(auto& dest : workers) {
        if(dest.first == params[0].asCStr()) {
            AmArg p = params;
            p.erase((size_t)0);
            res = dest.second->getConnectionLog(p);
        }
    }
    ret = res;
}

bool PostgreSQL::showConfiguration(const string& connection_id,
                           const AmArg& request_id,
                           const AmArg& params)
{
    postEvent(new JsonRpcRequestEvent(
        connection_id, request_id, false,
        MethodShowConfig, params));
    return true;
}

void PostgreSQL::showConfig(const AmArg&, AmArg& ret)
{
    AmArg& wrs_arr = ret["workers"];
    for(auto& dest : workers) {
        AmArg& worker = wrs_arr[dest.first.c_str()];
        dest.second->getConfig(worker);
    }
}

void PostgreSQL::requestReconnect(const AmArg& args, AmArg&)
{
    if(!args.size() ||
       !isArgCStr(args[0]) || 
       (args.size() > 1 && !isArgCStr(args[1])) ||
       (args.size() > 1 && strcmp(args[1].asCStr(), "master") && strcmp(args[1].asCStr(), "slave"))) {
        throw AmSession::Exception(500, "usage: postgresql.request.reconnect <worker name> [master | slave]");
    }

    if(args.size() > 1) {
        PGWorkerPoolCreate::PoolType type = (strcmp(args[1].asCStr(), "master") ? PGWorkerPoolCreate::Slave : PGWorkerPoolCreate::Master);
        postEvent(new ResetEvent(args[0].asCStr(), type));
    } else {
        postEvent(new ResetEvent(args[0].asCStr()));
    }
}

void PostgreSQL::requestReset(const AmArg& args, AmArg&)
{
    if(args.size() != 2 ||
       !isArgCStr(args[0])) {
        throw AmSession::Exception(500, "usage: postgresql.request.reset <worker name> <connection fd>");
    }

    int fd = 0;
    if(isArgInt(args[1]))
        fd = args[1].asInt();
    else if(isArgCStr(args[1])) {
        if(!str2int(args[1].asCStr(), fd)) {
            throw AmSession::Exception(500, "usage: postgresql.request.reset <worker name> <connection fd>");
        }
    } else {
        throw AmSession::Exception(500, "usage: postgresql.request.reset <worker name> <connection fd>");
    }

    postEvent(new ResetEvent(args[0].asCStr(), fd));
}

bool PostgreSQL::transLog(const string& connection_id,
                           const AmArg& request_id,
                           const AmArg& params)
{
    if(params.size() != 3 ||
       !isArgCStr(params[0]) ||
       !isArgCStr(params[2])) {
        throw AmSession::Exception(500, "usage: postgresql.request.get_connection_log <worker name> <connection fd> <file path>");
    }

    int fd = 0;
    if(isArgInt(params[1]))
        fd = params[1].asInt();
    else if(isArgCStr(params[1])) {
        if(!str2int(params[1].asCStr(), fd)) {
            throw AmSession::Exception(500, "usage: postgresql.request.get_connection_log <worker name> <connection fd> <file path>");
        }
    } else {
        throw AmSession::Exception(500, "usage: postgresql.request.get_connection_log <worker name> <connection fd> <file path>");
    }

    postEvent(new JsonRpcRequestEvent(
        connection_id, request_id, false,
        MethodTransLog, params));
    return true;
}

void PostgreSQL::init_rpc_tree()
{
    AmArg &show = reg_leaf(root,"show");
        reg_method(show, "stats", "show statistics", &PostgreSQL::showStatistics);
        reg_method(show, "config", "show config", &PostgreSQL::showConfiguration);
    AmArg &request = reg_leaf(root,"request");
        reg_method(request, "reconnect", "reset pq connection", &PostgreSQL::requestReconnect);
        reg_method(request, "reset", "reset pq connection", &PostgreSQL::requestReset);
        reg_method(request, "get_connection_log", "get log of pq connection", &PostgreSQL::transLog);
}

void PostgreSQL::process(AmEvent* ev)
{
    switch(ev->event_id) {
    case JSONRPC_EVENT_ID:
        if(auto e = dynamic_cast<JsonRpcRequestEvent *>(ev))
            process_jsonrpc_request(*e);
        break;
    case E_SYSTEM: {
        AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(ev);
        if(sys_ev && sys_ev->sys_event == AmSystemEvent::ServerShutdown){
            stop_event.fire();
        }

    } break;
    default:
        process_postgres_event(ev);
    }
}

void PostgreSQL::process_postgres_event(AmEvent* ev)
{
    switch(ev->event_id) {
    case PGEvent::WorkerPoolCreate: {
        if(PGWorkerPoolCreate *e = dynamic_cast<PGWorkerPoolCreate*>(ev))
            onWorkerPoolCreate(*e);
    } break;
    case PGEvent::WorkerConfig: {
        if(PGWorkerConfig *e = dynamic_cast<PGWorkerConfig*>(ev))
            onWorkerConfig(*e);
    } break;
    case PGEvent::WorkerDestroy: {
        if(PGWorkerDestroy *e = dynamic_cast<PGWorkerDestroy*>(ev))
            onWorkerDestroy(*e);
    } break;
    case PGEvent::SetSearchPath: {
        if(PGSetSearchPath *e = dynamic_cast<PGSetSearchPath*>(ev))
            onSetSearchPath(*e);
    }
    case PGEvent::SimpleExecute: {
        if(PGExecute *e = dynamic_cast<PGExecute*>(ev))
            onSimpleExecute(*e);
    } break;
    case PGEvent::ParamExecute: {
        if(PGParamExecute *e = dynamic_cast<PGParamExecute*>(ev))
            onParamExecute(*e);
    } break;
    case PGEvent::Prepare: {
        if(PGPrepare *e = dynamic_cast<PGPrepare*>(ev))
            onPrepare(*e);
    } break;
    case PGEvent::PrepareExec: {
        if(PGPrepareExec *e = dynamic_cast<PGPrepareExec*>(ev))
            onPrepareExecute(*e);
    } break;
    case AdditionalTypeEvent::Reset: {
        if(ResetEvent *e = dynamic_cast<ResetEvent*>(ev))
            onReset(*e);
    } break;
    }
}

void PostgreSQL::process_jsonrpc_request(JsonRpcRequestEvent& request)
{
    switch(request.method_id) {
    case MethodShowStats: {
        AmArg ret;
        showStats(request.params, ret);
        postJsonRpcReply(request, ret);
    } break;
    case MethodTransLog: {
        AmArg ret;
        getConnectionLog(request.params, ret);
        postJsonRpcReply(request, ret);
    } break;
    case MethodShowConfig: {
        AmArg ret;
        showConfig(request.params, ret);
        postJsonRpcReply(request, ret);
    } break;
    }
}

Worker* PostgreSQL::getWorker(const PGQueryData& e)
{
    if(workers.find(e.worker_name) == workers.end()) {
        ERROR("worker %s not found", e.worker_name.c_str());
        if(!e.sender_id.empty())
            AmSessionContainer::instance()->postEvent(
                e.sender_id, new PGResponseError("worker not found", e.token));
        return 0;
    }
    return workers[e.worker_name];
}

bool PostgreSQL::checkQueryData(const PGQueryData& data)
{
    if(data.info.empty()) {
        AmSessionContainer::instance()->postEvent(
            data.sender_id, new PGResponseError("absent query", data.token));
        return false;
    }
    return true;
}

void PostgreSQL::onWorkerPoolCreate(const PGWorkerPoolCreate& e)
{
    if(workers.find(e.worker_name) == workers.end()) {
        workers[e.worker_name] = new Worker(e.worker_name, epoll_fd);
    }
    Worker* worker = workers[e.worker_name];
    worker->createPool(e.type, e.pool);
}

void PostgreSQL::onSimpleExecute(const PGExecute& e)
{
    if(!checkQueryData(e.qdata)) return;

    Worker* worker = getWorker(e.qdata);
    if(!worker) return;

    IPGQuery* query = new QueryParams(e.qdata.info[0].query, e.qdata.info[0].single, false);
    if(e.qdata.info.size() > 1) {
        QueryChain* chain = new QueryChain(query);
        for(size_t i = 1;i < e.qdata.info.size(); i++) {
            chain->addQuery(new QueryParams(e.qdata.info[i].query, e.qdata.info[i].single, false));
        }
        query = chain;
    }

    if(!e.initial) {
        IPGTransaction* trans = 0;
        if(!e.tdata.use_transaction)
            trans = new NonTransaction(worker);
        else
            trans = createDbTransaction(worker, e.tdata.il, e.tdata.wp);

        trans->exec(query);
        worker->runTransaction(trans, e.qdata.sender_id, e.qdata.token);
    } else {
        worker->runInitial(query);
    }
}

void PostgreSQL::onParamExecute(const PGParamExecute& e)
{
    if(!checkQueryData(e.qdata)) return;

    Worker* worker = getWorker(e.qdata);
    if(worker) {
        QueryParams* qparams = new QueryParams(e.qdata.info[0].query, e.qdata.info[0].single, e.prepared);
        qparams->addParams(getParams(e.qdata.info[0].params));
        IPGQuery* query = qparams;
        if(e.qdata.info.size() > 1) {
            QueryChain* chain = new QueryChain(query);
            for(size_t i = 1;i < e.qdata.info.size(); i++) {
                qparams = new QueryParams(e.qdata.info[i].query, e.qdata.info[i].single, e.prepared);
                qparams->addParams(getParams(e.qdata.info[i].params));
                chain->addQuery(qparams);
            }
            query = chain;
        }

        if(!e.initial) {
            IPGTransaction* trans = 0;
            if(!e.tdata.use_transaction)
                trans = new NonTransaction(worker);
            else
                trans = createDbTransaction(worker, e.tdata.il, e.tdata.wp);

            trans->exec(query);
            worker->runTransaction(trans, e.qdata.sender_id, e.qdata.token);
        } else {
            worker->runInitial(query);
        }
    }
}

void PostgreSQL::onPrepare(const PGPrepare& e)
{
    PGQueryData data(e.worker_name, e.pdata.query, false, "");
    Worker* worker = getWorker(data);
    if(worker) {
        worker->runPrepared(e.pdata);
    }
}

void PostgreSQL::onPrepareExecute(const PGPrepareExec& e)
{
    Worker* worker = getWorker(PGQueryData(e.worker_name, e.sender_id, e.token));
    if(worker) {
        worker->runTransaction(new PreparedTransaction(e, worker), e.sender_id, e.token);
    }
}

void PostgreSQL::onWorkerDestroy(const PGWorkerDestroy& e)
{
    auto worker_it = workers.find(e.worker_name);
    if(worker_it != workers.end()) {
        delete worker_it->second;
        workers.erase(worker_it);
    } else {
        WARN("worker %s not found", e.worker_name.c_str());
    }
}

void PostgreSQL::onWorkerConfig(const PGWorkerConfig& e)
{
    if(workers.find(e.worker_name) == workers.end()) {
        ERROR("worker %s not found", e.worker_name.c_str());
        return;
    }
    Worker* worker = workers[e.worker_name];
    worker->configure(e);
}

void PostgreSQL::onSetSearchPath(const PGSetSearchPath& e)
{
    if(workers.find(e.worker_name) == workers.end()) {
        ERROR("worker %s not found", e.worker_name.c_str());
        return;
    }
    Worker* worker = workers[e.worker_name];
    worker->setSearchPath(e.search_pathes);
}

void PostgreSQL::onReset(const ResetEvent& e) {
    for(auto& dest : workers) {
        if(dest.first == e.worker_name) {
            if(e.type == ResetEvent::PoolTypeReset) {
                dest.second->resetPools(e.data.type);
            } else if(e.type == ResetEvent::FdReset){
                dest.second->resetConnection(e.data.fd);
            } else {
                dest.second->resetPools();
            }
        }
    }
}

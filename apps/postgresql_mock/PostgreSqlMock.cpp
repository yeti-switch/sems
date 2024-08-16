#include "PostgreSqlMock.h"
#include "log.h"
#include "AmEventDispatcher.h"
#include "Config.h"

#include <jsonArg.h>

#define eventDispatcher     AmEventDispatcher::instance()
#define sessionContainer    AmSessionContainer::instance()

#define EPOLL_MAX_EVENTS            2048
#define POSTGRESQL_QUEUE_MOCK       "postgresql"

class PostgreSqlMockFactory
  : public AmDynInvokeFactory
  , public AmConfigFactory
{
    PostgreSqlMockFactory(const string& name)
      : AmDynInvokeFactory(name)
      , AmConfigFactory(name)
    {
        PostgreSqlMock::instance();
    }
    ~PostgreSqlMockFactory()
    {
        INFO("~PostgreSqlMockFactory");
        PostgreSqlMock::dispose();
    }
  public:
    DECLARE_FACTORY_INSTANCE(PostgreSqlMockFactory);

    AmDynInvoke* getInstance() {
        return PostgreSqlMock::instance();
    }

    int onLoad() {
        return PostgreSqlMock::instance()->onLoad();
    }

    void on_destroy() {
        PostgreSqlMock::instance()->stop();
    }

    int configure(const string& config) {
        return PostgreSqlMock::instance()->configure(config);
    }

    int reconfigure(const string& config) {
        return PostgreSqlMock::instance()->reconfigure(config);
    }
};

EXPORT_PLUGIN_CLASS_FACTORY(PostgreSqlMockFactory);
EXPORT_PLUGIN_CONF_FACTORY(PostgreSqlMockFactory);
DEFINE_FACTORY_INSTANCE(PostgreSqlMockFactory, MOD_NAME);

PostgreSqlMock* PostgreSqlMock::_instance=0;

PostgreSqlMock* PostgreSqlMock::instance()
{
    if(_instance == nullptr)
        _instance = new PostgreSqlMock();

    return _instance;
}


void PostgreSqlMock::dispose()
{
    if(_instance != nullptr){
        delete _instance;
        _instance = nullptr;
    }
}

PostgreSqlMock::PostgreSqlMock()
 : AmEventFdQueue(this)
{
    eventDispatcher->addEventQueue(POSTGRESQL_QUEUE_MOCK, this);
}

PostgreSqlMock::~PostgreSqlMock()
{
    eventDispatcher->delEventQueue(POSTGRESQL_QUEUE_MOCK);
}

int PostgreSqlMock::onLoad()
{
    if(init()){
        ERROR("initialization error");
        return -1;
    }

    start();
    return 0;
}

int PostgreSqlMock::configure(const string& config)
{
    cfg_t *cfg = cfg_init(pg_opts, CFGF_NONE);
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

    cfg_free(cfg);
    return 0;
}

int PostgreSqlMock::reconfigure(const string& config)
{
    return configure(config);
}

int PostgreSqlMock::init()
{
    if((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    epoll_link(epoll_fd, true);
    stop_event.link(epoll_fd,true);
    init_rpc();

    DBG("PostgreSqlMock Client initialized");
    return 0;
}

/* AmThread */

void PostgreSqlMock::run()
{
    void *p;
    bool running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    setThreadName("pg-client-mock");

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
            }
        }
    } while(running);

    epoll_unlink(epoll_fd);
    close(epoll_fd);

    DBG("PostgreSqlMock Client stopped");

    stopped.set(true);
}

void PostgreSqlMock::on_stop()
{
    stop_event.fire();
    stopped.wait_for();
}

/* rpc handlers */

void PostgreSqlMock::stackPush(const AmArg& args, AmArg&)
{
    if(args.size() == 0) return;

    auto response = new Response();
    response->value = arg2str(args[0]);
    if(args.size() > 1) response->error = arg2str(args[1]);
    if(args.size() > 2) response->timeout = (arg2str(args[2]) == "true");

    resp_stack.emplace_back(response);
}

void PostgreSqlMock::stackClear(const AmArg& args, AmArg&)
{
    resp_stack.clear();
}

void PostgreSqlMock::stackShow(const AmArg& args, AmArg& ret)
{
    for(auto & it : resp_stack) {
        ret.push(AmArg());
        AmArg &r = ret.back();
        r.push(AmArg(it->value));
        r.push(AmArg(it->error));
        r.push(AmArg(it->timeout));
    }
}

void PostgreSqlMock::mapInsert(const AmArg& args, AmArg&)
{
    if(args.size() == 0) return;

    auto resp = new Response();
    if(args.size() > 1) resp->value = arg2str(args[1]);
    if(args.size() > 2) resp->error = arg2str(args[2]);
    if(args.size() > 3) resp->timeout = (arg2str(args[3]) == "true");

    resp_map.try_emplace(arg2str(args[0])/*query*/, resp);
}

void PostgreSqlMock::mapClear(const AmArg& args, AmArg&)
{
    resp_map.clear();
}

void PostgreSqlMock::mapShow(const AmArg& args, AmArg& ret)
{
    ret.assertArray();
    for(auto & it : resp_map) {
        ret.push(AmArg());
        AmArg &r = ret.back();
        r.push(AmArg(it.first.c_str()/*query*/));
        r.push(AmArg(it.second->value.c_str()));
        r.push(AmArg(it.second->error.c_str()));
        r.push(AmArg(it.second->timeout));
    }
}

/* RpcTreeHandler */

void PostgreSqlMock::init_rpc_tree()
{
    AmArg &stack = reg_leaf(root,"stack");
    reg_method(stack, "push", "stack push", &PostgreSqlMock::stackPush);
    reg_method(stack, "clear", "stack clear", &PostgreSqlMock::stackClear);
    reg_method(stack, "show", "stack show", &PostgreSqlMock::stackShow);
    AmArg &map = reg_leaf(root,"map");
    reg_method(map, "insert", "map insert", &PostgreSqlMock::mapInsert);
    reg_method(map, "clear", "map clear", &PostgreSqlMock::mapClear);
    reg_method(map, "show", "map show", &PostgreSqlMock::mapShow);
}

/* AmEventHandler */

void PostgreSqlMock::process(AmEvent* ev)
{
    switch(ev->event_id) {
        case E_SYSTEM: {
            if(AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(ev)) {
                switch(sys_ev->sys_event) {
                    case AmSystemEvent::ServerShutdown:
                        stop_event.fire();
                        break;
                    default:
                        break;
                }
            }
        } break;
        default:
            process_postgres_event(ev);
    }
}

void PostgreSqlMock::process_postgres_event(AmEvent* ev)
{
    switch(ev->event_id) {
        case PGEvent::SimpleExecute: {
            if(PGExecute *e = dynamic_cast<PGExecute*>(ev))
                onSimpleExecute(*e);
        } break;
        case PGEvent::ParamExecute: {
            if(PGParamExecute *e = dynamic_cast<PGParamExecute*>(ev))
                onParamExecute(*e);
        } break;
        case PGEvent::PrepareExec: {
            if(PGPrepareExec *e = dynamic_cast<PGPrepareExec*>(ev))
                onPrepareExecute(*e);
        } break;
    }
}

bool PostgreSqlMock::checkQueryData(const PGQueryData& data)
{
    if(data.info.empty()) {
        sessionContainer->postEvent(data.sender_id, new PGResponseError("absent query", data.token));
        return false;
    }

    return true;
}

PostgreSqlMock::Response* PostgreSqlMock::find_resp_for_query(const string& query)
{
    auto resp_it = resp_map.find(query);
    if(resp_it == resp_map.end()) {
        if(resp_stack.empty())
            return nullptr;

        auto resp = resp_stack.back().release();
        resp_stack.pop_back();
        return resp;
    }

    return resp_it->second.get();
}

void PostgreSqlMock::handle_query(const string& query, const string& sender_id, const string& token)
{
    const auto response = find_resp_for_query(query);
    if(!response) return;

    if(!response->error.empty()) {
        sessionContainer->postEvent(sender_id, new PGResponseError(response->error, token));
        return;
    }

    if(response->timeout) {
        sessionContainer->postEvent(sender_id, new PGTimeout(token));
        return;
    }

    AmArg resp_arg;
    if(!json2arg(response->value, resp_arg)) {
        DBG("json2arg failed for value '%s'", response->value.c_str());
        return;
    }

    sessionContainer->postEvent(sender_id, new PGResponse(resp_arg, token));
}

void PostgreSqlMock::handle_query_data(const PGQueryData& qdata)
{
    for(auto qinfo : qdata.info)
        handle_query(qinfo.query, qdata.sender_id, qdata.token);
}

void PostgreSqlMock::onSimpleExecute(const PGExecute& e)
{
    if(!checkQueryData(e.qdata)) return;
    handle_query_data(e.qdata);
}

void PostgreSqlMock::onParamExecute(const PGParamExecute& e)
{
    if(!checkQueryData(e.qdata)) return;
    handle_query_data(e.qdata);
}

void PostgreSqlMock::onPrepareExecute(const PGPrepareExec& e)
{
    handle_query(e.info.query, e.sender_id, e.token);
}

void PostgreSqlMock::insert_resp_map(const string& query, const string& resp, const string& error, bool timeout)
{
    DBG("query [%s]: \n\t - value: %s \n\t - error: %s \n\t - timout: %d", query.c_str(), resp.c_str(), error.c_str(), timeout);
    auto response = new Response();
    response->value = resp;
    response->error = error;
    response->timeout = timeout;
    resp_map.try_emplace(query, response);
}

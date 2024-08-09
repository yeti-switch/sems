#include "PostgreSqlMock.h"

#include "log.h"
#include "AmEventDispatcher.h"
#include "Config.h"

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

    cfg_t *cfg_map = cfg_getsec(cfg, CFG_OPT_MAP);

    for(int i = 0; i < cfg_size(cfg_map, CFG_OPT_PAIR); ++i) {
        cfg_t *cfg_pair = cfg_getnsec(cfg_map, CFG_OPT_PAIR, i);
        auto query = cfg_getstr(cfg_pair, CFG_OPT_QUERY);
        auto response = cfg_getstr(cfg_pair, CFG_OPT_RESPONSE);
        resp_map[query] = response;
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

void PostgreSqlMock::stackPush(const AmArg& args, AmArg&)
{
    for(int i = 0; i < args.size(); ++i)
        resp_stack.emplace_back(arg2str(args[i]));
}

void PostgreSqlMock::stackClear(const AmArg& args, AmArg&)
{
    resp_stack.clear();
}

void PostgreSqlMock::stackShow(const AmArg& args, AmArg& ret)
{
    for(auto & it : resp_stack)
        ret.push(AmArg(it.c_str()));
}

void PostgreSqlMock::mapInsert(const AmArg& args, AmArg&)
{
    resp_map[arg2str(args[0])] = arg2str(args[1]);
}

void PostgreSqlMock::mapClear(const AmArg& args, AmArg&)
{
    resp_map.clear();
}

void PostgreSqlMock::mapShow(const AmArg& args, AmArg& ret)
{
    ret.assertArray();
    for(auto it : resp_map) {
        ret.push(AmArg());
        AmArg &r = ret.back();
        r.push(AmArg(it.first.c_str()));
        r.push(AmArg(it.second.c_str()));
    }
}

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

string PostgreSqlMock::find_resp_for_query(const string& query)
{
    string response = resp_map[query];

    if(response.empty()) {
        response = resp_stack.back();
        resp_stack.pop_back();
    }

    return response;
}

void PostgreSqlMock::handle_query(const string& query, const string& sender_id, const string& token)
{
    const string response = find_resp_for_query(query);

    if(!response.empty())
        sessionContainer->postEvent(sender_id, new PGResponse(response, token));
    else
        sessionContainer->postEvent(sender_id, new PGResponseError("response is unavailable", token));
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

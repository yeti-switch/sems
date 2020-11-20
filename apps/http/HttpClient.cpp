#include "HttpClient.h"

#include "log.h"

#include "AmSessionContainer.h"
#include "AmUtils.h"
#include "sip/resolver.h"

#define MOD_NAME "http_client"

#include <vector>
#include "http_client_cfg.h"
using std::vector;

#define SYNC_CONTEXTS_TIMER_INVERVAL 500000
#define SYNC_CONTEXTS_TIMEOUT_INVERVAL 60 //seconds

class HttpClientFactory
  : public AmDynInvokeFactory
  , public AmConfigFactory
{
    HttpClientFactory(const string& name)
      : AmDynInvokeFactory(name)
      , AmConfigFactory(name)
    {
        HttpClient::instance();
    }
    ~HttpClientFactory()
    {
        INFO("~HttpClientFactory");
        HttpClient::dispose();
    }
  public:
    DECLARE_FACTORY_INSTANCE(HttpClientFactory);

    int configure(const string& config)
    {
        return HttpClient::instance()->configure(config);
    }

    int reconfigure(const std::string& config)
    {
        return configure(config);
    }

    AmDynInvoke* getInstance()
    {
        return HttpClient::instance();
    }
    int onLoad()
    {
        return HttpClient::instance()->onLoad();
    }
    void on_destroy() {
        HttpClient::instance()->stop();
    }
};

EXPORT_PLUGIN_CLASS_FACTORY(HttpClientFactory);
EXPORT_PLUGIN_CONF_FACTORY(HttpClientFactory);
DEFINE_FACTORY_INSTANCE(HttpClientFactory, MOD_NAME);

HttpClient* HttpClient::_instance=0;

HttpClient* HttpClient::instance()
{
    if(_instance == NULL){
        _instance = new HttpClient();
    }
    return _instance;
}


void HttpClient::dispose()
{
    if(_instance != NULL){
        delete _instance;
    }
    _instance = NULL;
}

HttpClient::HttpClient()
  : AmEventFdQueue(this),
    epoll_fd(-1),
    stopped(false)
{ 
    stat_group(Gauge, MOD_NAME, "sync_context_count").addFunctionCounter([]()->unsigned long long {
       return HttpClient::instance()->sync_contexts.size();
    });
}

HttpClient::~HttpClient()
{ }

int validate_mode_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    HttpDestination::Mode mode = HttpDestination::str2Mode(value);
    if(mode == HttpDestination::Unknown) {
        ERROR("invalid value \'%s\' of option \'%s\' - must be \'put\' or \'post\'", value.c_str(), opt->name);
        return 1;
    }
    return 0;
}

int validate_action_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    DestinationAction::HttpAction action = DestinationAction::str2Action(value);
    if(action == DestinationAction::Unknown) {
        ERROR("invalid value \'%s\' of option \'%s\' - must be \'move\', \'nothing\', \'remove\' or \'requeue\'", value.c_str(), opt->name);
        return 1;
    }
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

int HttpClient::configure(const string& config)
{
    cfg_t *cfg = cfg_init(http_client_opt, CFGF_NONE);
    if(!cfg) return -1;
    cfg_set_validate_func(cfg, SECTION_DIST_NAME "|" PARAM_MODE_NAME, validate_mode_func);
    cfg_set_validate_func(cfg, SECTION_DIST_NAME "|" SECTION_ON_SUCCESS_NAME "|" PARAM_ACTION_NAME, validate_action_func);
    cfg_set_validate_func(cfg, SECTION_DIST_NAME "|" SECTION_ON_FAIL_NAME "|" PARAM_ACTION_NAME, validate_action_func);
    cfg_set_error_function(cfg,cfg_error_callback);

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

    resend_interval = cfg_getint(cfg, PARAM_RESEND_INTERVAL_NAME)*1000;
    DefaultValues vals;
    vals.resend_queue_max = resend_queue_max = cfg_getint(cfg, PARAM_RESEND_QUEUE_MAX_NAME);
    vals.resend_connection_limit = resend_connection_limit = cfg_getint(cfg, PARAM_RESEND_CONNECTION_LIMIT_NAME);
    vals.connection_limit = connection_limit = cfg_getint(cfg, PARAM_CONNECTION_LIMIT_NAME);

    destinations.clear();
    if(destinations.configure(cfg, vals)){
        ERROR("can't configure destinations");
        cfg_free(cfg);
        return -1;
    }
    destinations.dump();

    cfg_free(cfg);
    return 0;
}

int HttpClient::init()
{
    if((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    if(destinations.need_requeue()) {
        resend_timer.link(epoll_fd,true);
        resend_timer.set(resend_interval);
    }

    sync_contexts_timer.link(epoll_fd,true);
    sync_contexts_timer.set(SYNC_CONTEXTS_TIMER_INVERVAL);

    resolve_timer.link(epoll_fd, true);
    resolve_timer.set(1, false);

    if(init_curl(epoll_fd)){
        ERROR("curl init failed");
        return -1;
    }

    epoll_link(epoll_fd,true);
    stop_event.link(epoll_fd,true);
    init_rpc();

    DBG("HttpClient initialized");
    return 0;
}

int HttpClient::onLoad()
{
    if(init()){
        ERROR("initialization error");
        return -1;
    }
    start();
    return 0;
}

void HttpClient::init_rpc_tree()
{
    AmArg &show = reg_leaf(root,"show");
        reg_method(show,"destinations","destinations dump",&HttpClient::dstDump);
        reg_method(show, "stats", "show statistics", &HttpClient::showStats);
        reg_method(show, "dns_cache", "show statistics", &HttpClient::showDnsCache);
    AmArg &post = reg_leaf(root,"request");
        reg_method(post,"post","post request", &HttpClient::postRequest);
        AmArg &cache = reg_leaf(post,"dns_cache");
            reg_method(cache,"reset","reset dns_cache", &HttpClient::resetDnsCache);
}

void HttpClient::postRequest(const AmArg& args, AmArg& ret)
{
    args.assertArrayFmt("ss");
    AmSessionContainer::instance()->postEvent(
        HTTP_EVENT_QUEUE,
        new HttpPostEvent(args.get(0).asCStr(), //destination
                          args.get(1).asCStr(), //data
                          string()));           //token
}

void HttpClient::dstDump(const AmArg&, AmArg& ret)
{
    destinations.dump(ret);
}

void HttpClient::showDnsCache(const AmArg& args, AmArg& ret)
{
    struct curl_slist* host = hosts;
    while(host) {
        ret.push(host->data);
        host = host->next;
    }
}

void HttpClient::resetDnsCache(const AmArg& args, AmArg& ret)
{
    resolve_timer.set(1);
}

void HttpClient::run()
{
    int ret;
    void *p;
    bool running;
    CurlConnection *c;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    setThreadName("http-client");

    AmEventDispatcher::instance()->addEventQueue(HTTP_EVENT_QUEUE, this);

    running = true;
    do {
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if(ret == -1 && errno != EINTR){
            ERROR("epoll_wait: %s\n",strerror(errno));
        }

        if(ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            p = e.data.ptr;

            CDBG("events = %d p = %p timer=%p queue_event=%p stop_event=%p",
                e.events, p, &curl_timer,static_cast<AmEventFdQueue *>(this),&stop_event);

            if(p==&curl_timer){
                on_timer_event();
            } else if(p==&resend_timer){
                on_resend_timer_event();
            } else if(p==&sync_contexts_timer) {
                on_sync_context_timer();
            } else if(p==&resolve_timer) {
                on_update_resolve_list();
            } else if(p==static_cast<AmEventFdQueue *>(this)){
                processEvents();
            } else if(p==&stop_event){
                stop_event.read();
                running = false;
                break;
            } else {
                if(invalid_ptrs.contain(p)){
                    CDBG("skip invalidated pointer %p",p);
                    continue;
                }
                c = reinterpret_cast<CurlConnection *>(p);
                on_socket_event(c,e.events);
            }
        }
        invalid_ptrs.clear();
    } while(running);

    AmEventDispatcher::instance()->delEventQueue(HTTP_EVENT_QUEUE);

    epoll_unlink(epoll_fd);
    close(epoll_fd);

    DBG("HttpClient stopped");

    stopped.set(true);
}

void HttpClient::on_stop()
{
    stop_event.fire();
    stopped.wait_for();
}

void HttpClient::process(AmEvent* ev)
{
    switch(ev->event_id) {
    case E_SYSTEM: {
        AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(ev);
        if(sys_ev && sys_ev->sys_event == AmSystemEvent::ServerShutdown){
            stop_event.fire();
        }

    } break;
    case HttpEvent::TriggerSyncContext: {
        if(HttpTriggerSyncContext *e = dynamic_cast<HttpTriggerSyncContext*>(ev))
            on_trigger_sync_context(*e);
    } break;
    default:
        process_http_event(ev);
    }
}

void HttpClient::process_http_event(AmEvent * ev)
{
    switch(ev->event_id) {
    case HttpEvent::Upload: {
        if(HttpUploadEvent *e = dynamic_cast<HttpUploadEvent*>(ev))
            on_upload_request(e);
    } break;
    case HttpEvent::Post: {
        if(HttpPostEvent *e = dynamic_cast<HttpPostEvent*>(ev))
            on_post_request(e);
    } break;
    case HttpEvent::MultiPartForm: {
        if(HttpPostMultipartFormEvent *e = dynamic_cast<HttpPostMultipartFormEvent*>(ev))
            on_multpart_form_request(e);
    } break;
    default:
        WARN("unknown event received");
    }
}

#define PASS_EVENT false
#define POSTPONE_EVENT true
template<typename EventType>
bool HttpClient::check_http_event_sync_ctx(const EventType &u)
{
    if(u.attempt) //skip requeued events
        return PASS_EVENT;

    if(u.sync_ctx_id.empty())
        return PASS_EVENT;

    auto it = sync_contexts.find(u.sync_ctx_id);
    if(it == sync_contexts.end()) {
        DBG("check_http_event_sync_ctx: no context '%s'. create new. postpone event",
            u.sync_ctx_id.c_str());

        EventType *e = new EventType(u);
        e->sync_ctx_id.clear();
        sync_contexts.emplace(u.sync_ctx_id,e);
        return POSTPONE_EVENT;
    }

    if(it->second.counter > 0) {
        DBG("check_http_event_sync_ctx: found positive context %s(%d). postpone event",
            u.sync_ctx_id.c_str(),it->second.counter);

        EventType *e = new EventType(u);
        e->sync_ctx_id.clear();
        it->second.add_event(e);
        return POSTPONE_EVENT;
    }

    DBG("check_http_event_sync_ctx: found negative context %s(%d). increase counter. pass event",
        u.sync_ctx_id.c_str(),it->second.counter);

    it->second.counter++;

    if(0==it->second.counter) {
        DBG("check_http_event_sync_ctx: context %s counter is 0. remove context",
            u.sync_ctx_id.c_str());

        if(it->second.postponed_events.size()) {
            auto &postponed_events = it->second.postponed_events;
            ERROR("check_http_event_sync_ctx: on removing context %s with counter 0. postponed events exist: %ld. reject them",
                  u.sync_ctx_id.c_str(),postponed_events.size());
            while(!postponed_events.empty()) {
                delete postponed_events.front();
                postponed_events.pop();
            }
        }

        sync_contexts.erase(it);
    }

    return PASS_EVENT;
}

void HttpClient::on_trigger_sync_context(const HttpTriggerSyncContext &e)
{
    auto it = sync_contexts.find(e.sync_ctx_id);
    if(it == sync_contexts.end()) {
        DBG("on_trigger_sync_context: no context '%s'. create new with counter %d",
            e.sync_ctx_id.c_str(),-e.quantity);
        sync_contexts.emplace(e.sync_ctx_id,-e.quantity);
        return;
    }

    DBG("on_trigger_sync_context: found context %s. counter %d. requeue postponed events and decrease counter by %d",
        e.sync_ctx_id.c_str(),it->second.counter,e.quantity);

    it->second.counter-=e.quantity;

    auto &postponed_events = it->second.postponed_events;
    while(!postponed_events.empty()) {
        process_http_event(postponed_events.front());
        delete postponed_events.front();
        postponed_events.pop();
    }

    if(it->second.counter < 0) {
        DBG("on_trigger_sync_context: finished. context %s. counter %d",
            e.sync_ctx_id.c_str(),it->second.counter);
        return;
    }

    if(it->second.counter > 0) {
        ERROR("on_trigger_sync_context: more than expected send events for syncronization context %s. "
              "remove it anyway. ",
               e.sync_ctx_id.c_str());
    }

    DBG("on_trigger_sync_context: remove context %s",
        e.sync_ctx_id.c_str());

    sync_contexts.erase(it);
}

void HttpClient::on_sync_context_timer()
{
    time_t now = time(nullptr);
    for(auto it = sync_contexts.begin(); it != sync_contexts.end(); ) {
        if(now - it->second.created_at > SYNC_CONTEXTS_TIMEOUT_INVERVAL) {
            auto &postponed_events = it->second.postponed_events;

            DBG("on_sync_context_timer: remove context %s, counter: %d on timeout. requeue postponed events %ld",
                it->first.c_str(),it->second.counter,postponed_events.size());

            while(!postponed_events.empty()) {
                process_http_event(postponed_events.front());
                delete postponed_events.front();
                postponed_events.pop();
            }

            it = sync_contexts.erase(it);

        } else {
            ++it;
        }
    }
    sync_contexts_timer.read();
}

void HttpClient::on_upload_request(HttpUploadEvent *u)
{
    HttpDestinationsMap::iterator destination = destinations.find(u->destination_name);
    if(destination==destinations.end()){
        ERROR("event with unknown destination '%s' from session %s. ignore it",
            u->destination_name.c_str(),u->session_id.c_str());
        return;
    }

    HttpDestination &d = destination->second;
    if(d.mode!=HttpDestination::Put) {
        ERROR("wrong destination '%s' type for upload request from session %s. 'put' mode expected. ignore it",
              u->destination_name.c_str(),u->session_id.c_str());
        return;
    }

    if(u->token.empty()){
        DBG("http upload request: %s => %s [%i/%i]",
            u->file_path.c_str(),
            d.url[u->failover_idx].c_str(),
            u->failover_idx,u->attempt);
    } else {
        DBG("http upload request: %s => %s [%i/%i] token: %s",
            u->file_path.c_str(),
            d.url[u->failover_idx].c_str(),
            u->failover_idx,u->attempt,
            u->token.c_str());
    }

    if(check_http_event_sync_ctx(*u)) {
        DBG("http upload request is consumed by synchronization contexts handler");
        return;
    }

    if(!u->attempt && d.count_connection.get() >= d.connection_limit) {
        DBG("http upload request marked as postponed");
        d.addEvent(new HttpUploadEvent(*u));
        return;
    }

    HttpUploadConnection *c = new HttpUploadConnection(*u,d,epoll_fd);
    if(c->init(hosts, curl_multi)){
        ERROR("http upload connection intialization error");
        delete c;
    }
}

void HttpClient::on_post_request(HttpPostEvent *u)
{
    HttpDestinationsMap::iterator destination = destinations.find(u->destination_name);
    if(destination==destinations.end()){
        ERROR("event with unknown destination '%s' from session %s. ignore it",
            u->destination_name.c_str(),u->session_id.c_str());
        return;
    }

    HttpDestination &d = destination->second;
    if(d.mode!=HttpDestination::Post) {
        ERROR("wrong destination '%s' mode for upload request from session %s. 'post' mode expected. ignore it",
              u->destination_name.c_str(),u->session_id.c_str());
        return;
    }

    if(u->token.empty()){
        DBG("http post request url: %s [%i/%i]",
            d.url[u->failover_idx].c_str(),
            u->failover_idx,u->attempt);
    } else {
        DBG("http post request url: %s [%i/%i], token: %s",
            d.url[u->failover_idx].c_str(),
            u->failover_idx,u->attempt,
            u->token.c_str());
    }

    if(check_http_event_sync_ctx(*u)) {
        DBG("http post request is consumed by synchronization contexts handler");
        return;
    }

    if(!u->attempt && d.count_connection.get() == d.connection_limit) {
        DBG("http post request marked as postponed");
        d.addEvent(new HttpPostEvent(*u));
        return;
    }

    HttpPostConnection *c = new HttpPostConnection(*u,d,epoll_fd);
    if(c->init(hosts, curl_multi)){
        ERROR("http post connection intialization error");
        delete c;
    }
}

void HttpClient::on_multpart_form_request(HttpPostMultipartFormEvent *u)
{
    HttpDestinationsMap::iterator destination = destinations.find(u->destination_name);
    if(destination==destinations.end()){
        ERROR("event with unknown destination '%s' from session %s. ignore it",
            u->destination_name.c_str(),u->session_id.c_str());
        return;
    }

    HttpDestination &d = destination->second;
    if(d.mode!=HttpDestination::Post) {
        ERROR("wrong destination '%s' mode for upload request from session %s. 'post' mode expected. ignore it",
              u->destination_name.c_str(),u->session_id.c_str());
        return;
    }

    if(u->token.empty()){
        DBG("http multipart form request url: %s [%i/%i]",
            d.url[u->failover_idx].c_str(),
            u->failover_idx,u->attempt);
    } else {
        DBG("http multipart form request url: %s [%i/%i], token: %s",
            d.url[u->failover_idx].c_str(),
            u->failover_idx,u->attempt,
            u->token.c_str());
    }

    if(check_http_event_sync_ctx(*u)) {
        DBG("multipart form request is consumed by synchronization contexts handler");
        return;
    }

    if(!u->attempt && d.count_connection.get() == d.connection_limit) {
        DBG("http multipart form request marked as postponed");
        d.addEvent(new HttpPostMultipartFormEvent(*u));
        return;
    }

    HttpMultiPartFormConnection *c = new HttpMultiPartFormConnection(*u,d,epoll_fd);
    if(c->init(hosts, curl_multi)){
        ERROR("http multipart form connection intialization error");
        delete c;
    }
}

void HttpClient::on_resend_timer_event()
{
    resend_timer.read();

    for(auto& dest : destinations) {
        dest.second.send_failed_events(this);
    }
}

static bool add_to_resolve_slist(struct curl_slist** hosts, const char* r_host)
{
    struct curl_slist* host = *hosts;
    int r_host_len = strlen(r_host);
    while(host) {
        int host_len = strlen(host->data);
        if(host_len == r_host_len && !strncmp(host->data, r_host, host_len)) return true;
        host = host->next;
    }

    struct curl_slist* tmp = curl_slist_append(*hosts, r_host);
    if(!tmp) {
        curl_slist_free_all(*hosts);
        return false;
    }

    *hosts = tmp; 
    return true;
}


void HttpClient::on_update_resolve_list()
{
    DBG("the cache is reset. trying update");
    resolve_timer.read();

    if(hosts) {
        curl_slist_free_all(hosts);
        hosts = 0;
    }

    CURLU *curlu = curl_url();
    if(!curlu) return;
    uint64_t next_time = -1;
    for(auto& dst : destinations) {
        for(auto& url : dst.second.url) {
            if(curl_url_set(curlu, CURLUPART_URL, url.c_str(), 0)) continue;
            char* host;
            curl_url_get(curlu, CURLUPART_HOST, &host, 0);
            char* port;
            curl_url_get(curlu, CURLUPART_PORT, &port, 0);

            dns_handle handle;
            sockaddr_storage sa;
            if(resolver::instance()->resolve_name(host, &handle, &sa, Dualstack) == -1)
                continue;
            if(next_time > handle.get_expired()) {
                next_time = handle.get_expired();
            }

            std::string rhost;
            rhost.append(host);
            rhost.append(":");
            if(port) rhost.append(port);
            else rhost.append("80");
            rhost.append(":");
            rhost.append(am_inet_ntop(&sa));
            while(handle.next_ip(&sa, Dualstack) != -1) {
                rhost.append(",");
                rhost.append(am_inet_ntop(&sa));
            }
            curl_free(host);
            if(port) curl_free(port);

            add_to_resolve_slist(&hosts, rhost.c_str());
        }
    }
    curl_url_cleanup(curlu);

    resolve_timer.set(next_time/1000);
}

void HttpClient::on_connection_delete(CurlConnection *c)
{
    invalid_ptrs.add(c);

    for(auto& dest : destinations) {
        dest.second.send_postponed_events(this);
    }
}

void HttpClient::showStats(const AmArg& args, AmArg &ret)
{
    ret["resend_interval"] = resend_interval;
    ret["sync_context_count"] = sync_contexts.size();
    for(auto& dest : destinations) {
        AmArg& dst_arr = ret["destinations"];
        AmArg& dst = dst_arr[dest.first.c_str()];
        dest.second.showStats(dst);
    }
}

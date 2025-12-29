#include "HttpClient.h"
#include "defs.h"
#include "log.h"
#include "format_helper.h"

#include "AmSessionContainer.h"
#include "AmEventDispatcher.h"
#include "AmUtils.h"
#include "sip/resolver.h"

#include "HttpUploadConnection.h"
#include "HttpPostConnection.h"
#include "HttpGetConnection.h"
#include "HttpMultipartFormConnection.h"

#include <vector>
#include "http_client_cfg.h"
using std::vector;

#include <sys/epoll.h>
#include <cJSON.h>
#include <botan/hex.h>
#include <botan/mac.h>
#include <botan/base64.h>

#define MOD_NAME "http_client"

#define SYNC_CONTEXTS_TIMER_INVERVAL   500000
#define SYNC_CONTEXTS_TIMEOUT_INVERVAL 60 // seconds
#define AUTH_TIMER_INVERVAL            2000000

static std::optional<string> get_url_resource(const string &url);
static string                get_rfc5322_date_str();
static string                compute_hmac_sha1(const string &msg, const string &key);

enum RpcMethodId { MethodShowDnsCache, MethodGetRequest, MethodPostRequest, MethodMultiRequest };

int HttpClient::events_log_level = L_DBG;

class HttpClientFactory : public AmDynInvokeFactory, public AmConfigFactory {
    HttpClientFactory(const string &name)
        : AmDynInvokeFactory(name)
        , AmConfigFactory(name)
    {
        HttpClient::instance();
    }
    ~HttpClientFactory() { HttpClient::dispose(); }

  public:
    DECLARE_FACTORY_INSTANCE(HttpClientFactory);

    int configure(const string &config) { return HttpClient::instance()->configure(config); }

    int reconfigure(const std::string &config) { return configure(config); }

    AmDynInvoke *getInstance() { return HttpClient::instance(); }
    int          onLoad() { return HttpClient::instance()->onLoad(); }
    void         on_destroy() { HttpClient::instance()->stop(); }
};

EXPORT_PLUGIN_CLASS_FACTORY(HttpClientFactory);
EXPORT_PLUGIN_CONF_FACTORY(HttpClientFactory);
DEFINE_FACTORY_INSTANCE(HttpClientFactory, MOD_NAME);

HttpClient *HttpClient::_instance = 0;

HttpClient *HttpClient::instance()
{
    if (_instance == nullptr) {
        _instance = new HttpClient();
    }
    return _instance;
}


void HttpClient::dispose()
{
    if (_instance != nullptr) {
        delete _instance;
    }
    _instance = nullptr;
}

HttpClient::HttpClient()
    : AmEventFdQueue(this)
    , ShutdownHandler(MOD_NAME, HTTP_EVENT_QUEUE)
    , epoll_fd(-1)
{
    stat_group(Gauge, MOD_NAME, "sync_context_count").addFunctionCounter([]() -> unsigned long long {
        return HttpClient::instance()->sync_contexts.size();
    });
}

HttpClient::~HttpClient() {}

static int validate_type_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string               value = cfg_getstr(cfg, opt->name);
    HttpDestination::AuthType type  = HttpDestination::str2AuthType(value);
    if (type == HttpDestination::AuthType_Unknown) {
        ERROR("invalid value \'%s\' of option \'%s\' - must be \'basic\' or \'firebase_oauth2\'", value.c_str(),
              opt->name);
        return 1;
    }
    return 0;
}

static int validate_mode_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string           value = cfg_getstr(cfg, opt->name);
    HttpDestination::Mode mode  = HttpDestination::str2Mode(value);
    if (mode == HttpDestination::Unknown) {
        ERROR("invalid value \'%s\' of option \'%s\' - must be \'put\' or \'post\'", value.c_str(), opt->name);
        return 1;
    }
    return 0;
}

static int validate_source_address_func(cfg_t *cfg, cfg_opt_t *opt)
{
    int         res;
    std::string value = cfg_getstr(cfg, opt->name);

    res = validate_ipv4_addr(value);
    if (res > 0)
        return 0;

    res = validate_ipv6_addr(value);
    if (res > 0)
        return 0;

    ERROR("invalid value \'%s\' of option \'%s\' - must be IPv4 or IPv6 address", value.c_str(), opt->name);
    return 1;
}

static int validate_action_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string                   value  = cfg_getstr(cfg, opt->name);
    DestinationAction::HttpAction action = DestinationAction::str2Action(value);
    if (action == DestinationAction::Unknown) {
        ERROR("invalid value \'%s\' of option \'%s\' - must be \'move\', \'nothing\', \'remove\' or \'requeue\'",
              value.c_str(), opt->name);
        return 1;
    }
    return 0;
}

long parse_size(const string &size)
{
    if (size.empty() || !isdigit(size[0]))
        return 0;
    char *endptr = nullptr;
    long  l_i    = strtol(size.c_str(), &endptr, 10);
    if (endptr && *endptr != '\0') {
        switch (*endptr) {
        case 'g':
        case 'G': l_i *= 1024;
        case 'm':
        case 'M': l_i *= 1024;
        case 'k':
        case 'K': l_i *= 1024; break;
        default:  return 0;
        }
        endptr++;
        if (endptr && *endptr != '\0')
            return 0;
    }
    return l_i;
}

static int validate_size_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    if (!parse_size(value)) {
        ERROR("invalid value \'%s\' of option \'%s\' - must be digital without or with one of 'g','G','m','M','k','K' "
              "symbols",
              value.c_str(), opt->name);
        return 1;
    }

    return 0;
}

void cfg_error_callback(cfg_t *cfg, const char *fmt, va_list ap)
{
    char  buf[2048];
    char *s = buf;
    char *e = s + sizeof(buf);

    if (cfg->title) {
        s += snprintf(s, e - s, "%s:%d [%s/%s]: ", cfg->filename, cfg->line, cfg->name, cfg->title);
    } else {
        s += snprintf(s, e - s, "%s:%d [%s]: ", cfg->filename, cfg->line, cfg->name);
    }
    s += vsnprintf(s, e - s, fmt, ap);

    ERROR("%.*s", (int)(s - buf), buf);
}

int HttpClient::configure(const string &config)
{
    cfg_t *cfg = cfg_init(http_client_opt, CFGF_NONE);
    if (!cfg)
        return -1;

    cfg_set_validate_func(cfg, PARAM_EVENTS_LOG_LEVEL, validate_log_func);
    cfg_set_validate_func(cfg, SECTION_AUTH_NAME "|" PARAM_AUTH_TYPE, validate_type_func);
    cfg_set_validate_func(cfg, SECTION_DEST_NAME "|" PARAM_MODE_NAME, validate_mode_func);
    cfg_set_validate_func(cfg, SECTION_DEST_NAME "|" PARAM_SOURCE_ADDRESS_NAME, validate_source_address_func);
    cfg_set_validate_func(cfg, SECTION_DEST_NAME "|" SECTION_ON_SUCCESS_NAME "|" PARAM_ACTION_NAME,
                          validate_action_func);
    cfg_set_validate_func(cfg, SECTION_DEST_NAME "|" SECTION_ON_FAIL_NAME "|" PARAM_ACTION_NAME, validate_action_func);
    cfg_set_validate_func(cfg, SECTION_DEST_NAME "|" PARAM_MAX_REPLY_SIZE_NAME, validate_size_func);
    cfg_set_validate_func(cfg, SECTION_DEST_NAME "|" PARAM_MIN_FILE_SIZE_NAME, validate_size_func);
    cfg_set_error_function(cfg, cfg_error_callback);

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

    resend_interval  = cfg_getint(cfg, PARAM_RESEND_INTERVAL_NAME) * 1000;
    events_log_level = parse_log_level(cfg_getstr(cfg, PARAM_EVENTS_LOG_LEVEL)).value_or(L_DBG);

    DefaultValues vals;
    vals.resend_queue_max = resend_queue_max = cfg_getint(cfg, PARAM_RESEND_QUEUE_MAX_NAME);
    vals.resend_connection_limit = resend_connection_limit = cfg_getint(cfg, PARAM_RESEND_CONNECTION_LIMIT_NAME);
    vals.connection_limit = connection_limit = cfg_getint(cfg, PARAM_CONNECTION_LIMIT_NAME);

    auths.clear();
    destinations.clear();

    if (destinations.configure(cfg, vals)) {
        ERROR("can't configure destinations");
        cfg_free(cfg);
        return -1;
    }

    for (auto &[name, dest] : destinations)
        if (dest.is_auth_destination)
            auths.emplace(name, &dest);

    for (const auto &[name, dest] : destinations) {
        if (!dest.auth_required.empty() && auths.find(dest.auth_required) == auths.end()) {
            ERROR("Destination '%s' has unknown auth '%s'", name.c_str(), dest.auth_required.c_str());
            return -1;
        }
    }

    destinations.dump();
    cfg_free(cfg);
    return 0;
}

int HttpClient::init()
{
    if ((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    if (destinations.need_requeue()) {
        resend_timer.link(epoll_fd, true);
        resend_timer.set(resend_interval);
    }

    auth_timer.link(epoll_fd, true);
    auth_timer.set(AUTH_TIMER_INVERVAL);

    sync_contexts_timer.link(epoll_fd, true);
    sync_contexts_timer.set(SYNC_CONTEXTS_TIMER_INVERVAL);


    resolve_timer.link(epoll_fd, true);
    // resolve_timer.set(1, false);
    update_resolve_list();

    if (init_curl(epoll_fd)) {
        ERROR("curl init failed");
        return -1;
    }

    epoll_link(epoll_fd, true);
    stop_event.link(epoll_fd, true);
    init_rpc();

    stat_group(Gauge, MOD_NAME, "failed_events").setHelp("resend events queue size");
    stat_group(Gauge, MOD_NAME, "active_connections").setHelp("active CURL handles in CURLM");
    stat_group(Gauge, MOD_NAME, "active_resend_connections").setHelp("active resend CURL handles in CURLM");
    stat_group(Gauge, MOD_NAME, "pending_events").setHelp("send events queue size");
    stat_group(Counter, MOD_NAME, "requests_processed").setHelp("requests completed in total, including failed ones");
    stat_group(Counter, MOD_NAME, "requests_failed").setHelp("requests failed in total");

    DBG("HttpClient initialized");
    return 0;
}

int HttpClient::onLoad()
{
    if (init()) {
        ERROR("initialization error");
        return -1;
    }
    start();
    return 0;
}

void HttpClient::init_rpc_tree()
{
    auto &show = reg_leaf(root, "show");
    reg_method(show, "auth", "auths dump", "", &HttpClient::authDump, this);
    reg_method(show, "destinations", "destinations dump", "", &HttpClient::dstDump, this);
    reg_method(show, "stats", "show statistics", "", &HttpClient::showStats, this);
    reg_method(show, "dns_cache", "show statistics", "", &HttpClient::showDnsCache, this);
    auto &req = reg_leaf(root, "request");
    reg_method(req, "post", "post request", "", &HttpClient::postRequest, this);
    reg_method(req, "get", "get request", "", &HttpClient::getRequest, this);
    reg_method(req, "multi", "multi request", "", &HttpClient::multiRequest, this);
    auto &cache = reg_leaf(req, "dns_cache");
    reg_method(cache, "reset", "reset dns_cache", "", &HttpClient::resetDnsCache, this);
    auto &set = reg_leaf(root, "set");
    reg_method(set, "events_log_level", "", "", &HttpClient::setEventsLogLevel, this);
}

bool HttpClient::postRequest(const string &connection_id, const AmArg &request_id, const AmArg &params)
{
    params.assertArrayFmt("ss");
    HttpDestinationsMap::iterator destination = destinations.find(params.get(0).asCStr());
    if (destination == destinations.end())
        throw(AmDynInvoke::Exception(-1, "unknown destination"));
    HttpDestination &d = destination->second;
    if (d.mode != HttpDestination::Post)
        throw(AmDynInvoke::Exception(-2, "wrong destination"));

    postEvent(new JsonRpcRequestEvent(connection_id, request_id, false, MethodPostRequest, params));
    return true;
}

bool HttpClient::getRequest(const string &connection_id, const AmArg &request_id, const AmArg &params)
{
    params.assertArrayFmt("ss");
    HttpDestinationsMap::iterator destination = destinations.find(params.get(0).asCStr());
    if (destination == destinations.end())
        throw(AmDynInvoke::Exception(-1, "unknown destination"));
    HttpDestination &d = destination->second;
    if (d.mode != HttpDestination::Get)
        throw(AmDynInvoke::Exception(-2, "wrong destination"));

    postEvent(new JsonRpcRequestEvent(connection_id, request_id, false, MethodGetRequest, params));
    return true;
}

bool HttpClient::multiRequest(const std::string &connection_id, const AmArg &request_id, const AmArg &params)
{
    params.assertArrayFmt("s");

    cJSON *data = cJSON_Parse(params.get(0).asCStr());
    if (!data || !data->child)
        throw(AmArg::TypeMismatchException());
    HttpMultiEvent *event = new HttpMultiEvent();
    event->sync_ctx_id    = AmSession::getNewId();
    for (cJSON *dst = data->child; dst; dst = dst->next) {
        HttpDestinationsMap::iterator destination = destinations.find(dst->string);
        if (destination == destinations.end()) {
            string err("unknown destination ");
            err += dst->string;
            throw(AmDynInvoke::Exception(-1, err));
        }
        cJSON *dst_val = cJSON_GetObjectItem(dst, "type");
        if (!dst_val || dst_val->type != cJSON_String) {
            string err("absent event type in destination ");
            err += dst->string;
            throw(AmDynInvoke::Exception(-1, err));
        }
        HttpEvent::Type type = HttpEvent::str2type(dst_val->valuestring);
        if (type == HttpEvent::Unknown) {
            string err("incorrect event type in destination ");
            err += dst->string;
            throw(AmDynInvoke::Exception(-1, err));
        }
        cJSON *data_val = cJSON_GetObjectItem(dst, "data");
        if (!data_val || data_val->type != cJSON_String) {
            string err("absent data in destination ");
            err += dst->string;
            throw(AmDynInvoke::Exception(-1, err));
        }

        string dst_name(dst->string);
        string data(data_val->valuestring);
        if (type == HttpEvent::Get) {
            event->add_event(new HttpGetEvent(dst_name, data, string()));
        } else if (type == HttpEvent::Post) {
            event->add_event(new HttpPostEvent(dst_name, data, string()));
        } else if (type == HttpEvent::Upload) {
            string file_name = filename_from_fullpath(data);
            if (file_name.empty())
                file_name = data;
            event->add_event(new HttpUploadEvent(dst_name, file_name, data, string()));
        }
    }

    postEvent(new JsonRpcRequestEvent(connection_id, request_id, false, MethodMultiRequest, AmArg((AmObject *)event)));
    return true;
}

void HttpClient::authDump(const AmArg &, AmArg &ret)
{
    ret.assertStruct();
    for (HttpAuthsMap::const_iterator i = auths.begin(); i != auths.end(); i++)
        i->second->dump(i->first, ret[i->first]);
}

void HttpClient::dstDump(const AmArg &, AmArg &ret)
{
    destinations.dump(ret);
}

bool HttpClient::showDnsCache(const string &connection_id, const AmArg &request_id, const AmArg &params)
{
    postEvent(new JsonRpcRequestEvent(connection_id, request_id, false, MethodShowDnsCache, params));

    return true;
}

void HttpClient::resetDnsCache(const AmArg &, AmArg &)
{
    resolve_timer.set(1);
}

void HttpClient::setEventsLogLevel(const AmArg &arg, AmArg &ret)
{
    if (!isArgArray(arg) || arg.size() < 1)
        throw AmDynInvoke::Exception(500, "expected array with log_level in the first item");

    try {
        int l            = arg2int(arg[0]);
        ret              = format("events_log_level changed {} -> {}", events_log_level, l);
        events_log_level = l;
    } catch (...) {
        throw AmDynInvoke::Exception(500, "failed to parse log_level");
    }
}


void HttpClient::run()
{
    int                ret;
    void              *p;
    bool               running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    setThreadName("http-client");

    AmEventDispatcher::instance()->addEventQueue(HTTP_EVENT_QUEUE, this);

    running = true;
    do {
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if (ret == -1 && errno != EINTR) {
            ERROR("epoll_wait: %s", strerror(errno));
        }

        if (ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            p                     = e.data.ptr;

            CDBG("events = %d p = %p timer=%p queue_event=%p stop_event=%p", e.events, p, &curl_timer,
                 static_cast<AmEventFdQueue *>(this), &stop_event);

            if (p == &curl_timer) {
                on_timer_event();
            } else if (p == &resend_timer) {
                on_resend_timer_event();
            } else if (p == &sync_contexts_timer) {
                on_sync_context_timer();
            } else if (p == &auth_timer) {
                on_auth_timer();
            } else if (p == &resolve_timer) {
                DBG("DNS cache timer expired");
                update_resolve_list();
            } else if (p == static_cast<AmEventFdQueue *>(this)) {
                processEvents();
            } else if (p == &stop_event) {
                stop_event.read();
                running = false;
                break;
            } else {
                on_socket_event(e.data.fd, e.events);
            }
        }
    } while (running);

    AmEventDispatcher::instance()->delEventQueue(HTTP_EVENT_QUEUE);

    epoll_unlink(epoll_fd);
    close(epoll_fd);

    DBG("HttpClient stopped");
}

void HttpClient::on_stop()
{
    stop_event.fire();
    join();
}

void HttpClient::process(AmEvent *ev)
{
    switch (ev->event_id) {
    case JSONRPC_EVENT_ID:
        if (auto e = dynamic_cast<JsonRpcRequestEvent *>(ev))
            process_jsonrpc_request(*e);
        break;
    case E_SYSTEM:
    {
        if (AmSystemEvent *sys_ev = dynamic_cast<AmSystemEvent *>(ev)) {
            switch (sys_ev->sys_event) {
            case AmSystemEvent::ServerShutdown:            stop_event.fire(); break;
            case AmSystemEvent::GracefulShutdownRequested: onShutdownRequested(); break;
            case AmSystemEvent::GracefulShutdownCancelled: onShutdownCancelled(); break;
            default:                                       break;
            }
        }
    } break;
    case HttpEvent::TriggerSyncContext:
    {
        if (HttpTriggerSyncContext *e = dynamic_cast<HttpTriggerSyncContext *>(ev))
            on_trigger_sync_context(*e);
    } break;
    default: process_http_event(ev);
    }

    checkFinished();
}

void HttpClient::process_jsonrpc_request(JsonRpcRequestEvent &request)
{
    switch (request.method_id) {
    case MethodShowDnsCache:
    {
        AmArg              ret;
        struct curl_slist *host = hosts;
        ret.assertArray();
        while (host) {
            ret.push(host->data);
            host = host->next;
        }
        postJsonRpcReply(request, ret);
    } break;
    case MethodGetRequest:
    {
        HttpGetEvent event(request.params.get(0).asCStr(), // destination
                           request.params.get(1).asCStr(), // url
                           string());                      // token
        event.sync_ctx_id = AmSession::getNewId();
        rpc_requests.emplace(event.sync_ctx_id, request);
        process_http_event(&event);
    } break;
    case MethodPostRequest:
    {
        HttpPostEvent event(request.params.get(0).asCStr(), // destination
                            request.params.get(1).asCStr(), // data
                            string());                      // token
        event.sync_ctx_id = AmSession::getNewId();
        rpc_requests.emplace(event.sync_ctx_id, request);
        sync_contexts.emplace(event.sync_ctx_id, -1);
        process_http_event(&event);
    } break;
    case MethodMultiRequest:
    {
        HttpMultiEvent *event = (HttpMultiEvent *)request.params.asObject();
        rpc_requests.emplace(event->sync_ctx_id, request);
        sync_contexts.emplace(event->sync_ctx_id, -1);
        process_http_event(event);
    } break;
    }
}

void HttpClient::process_http_event(AmEvent *ev)
{
    switch (ev->event_id) {
    case HttpEvent::Upload:
    {
        if (HttpUploadEvent *e = dynamic_cast<HttpUploadEvent *>(ev))
            on_upload_request(e);
    } break;
    case HttpEvent::Post:
    {
        if (HttpPostEvent *e = dynamic_cast<HttpPostEvent *>(ev))
            on_post_request(e);
    } break;
    case HttpEvent::MultiPartForm:
    {
        if (HttpPostMultipartFormEvent *e = dynamic_cast<HttpPostMultipartFormEvent *>(ev))
            on_multpart_form_request(e);
    } break;
    case HttpEvent::Get:
    {
        if (HttpGetEvent *e = dynamic_cast<HttpGetEvent *>(ev))
            on_get_request(e);
    } break;
    case HttpEvent::Multi:
    {
        if (HttpMultiEvent *e = dynamic_cast<HttpMultiEvent *>(ev))
            on_multi_request(e);
    } break;
    default: WARN("unknown event received. event_id:%d", ev->event_id);
    }
}

#define PASS_EVENT     false
#define POSTPONE_EVENT true
template <typename EventType> bool HttpClient::check_http_event_sync_ctx(const EventType &u)
{
    if (u.attempt) // skip requeued events
        return PASS_EVENT;

    if (u.sync_ctx_id.empty())
        return PASS_EVENT;

    auto it = sync_contexts.find(u.sync_ctx_id);
    if (it == sync_contexts.end()) {
        DBG("check_http_event_sync_ctx: no context '%s'. create new. postpone event", u.sync_ctx_id.c_str());

        EventType *e = new EventType(u);
        e->sync_ctx_id.clear();
        sync_contexts.emplace(u.sync_ctx_id, e);
        return POSTPONE_EVENT;
    }

    if (it->second.counter > 0) {
        DBG("check_http_event_sync_ctx: found positive context %s(%d). postpone event", u.sync_ctx_id.c_str(),
            it->second.counter);

        EventType *e = new EventType(u);
        e->sync_ctx_id.clear();
        it->second.add_event(e);
        return POSTPONE_EVENT;
    }

    DBG("check_http_event_sync_ctx: found context %s(%d). increase counter. pass event", u.sync_ctx_id.c_str(),
        it->second.counter);

    it->second.counter++;

    if (0 == it->second.counter) {
        DBG("check_http_event_sync_ctx: context %s counter is 0. remove context", u.sync_ctx_id.c_str());

        if (it->second.postponed_events.size()) {
            auto &postponed_events = it->second.postponed_events;
            ERROR("check_http_event_sync_ctx: on removing context %s with counter 0. postponed events exist: %ld. "
                  "reject them",
                  u.sync_ctx_id.c_str(), postponed_events.size());
            while (!postponed_events.empty()) {
                delete postponed_events.front();
                postponed_events.pop();
            }
        }

        sync_contexts.erase(it);
    }

    return PASS_EVENT;
}

bool HttpClient::checkMultiResponse(const DestinationAction &action, string &connection_id)
{
    auto it = multi_data_entries.find(connection_id);
    if (it != multi_data_entries.end()) {
        string sync_token = it->second.sync_token;
        multi_data_entries.erase(it);

        SyncMultiData &smd = sync_multies.at(sync_token);
        DBG("found ctx for: %s. sync_token:%s, counter:%d", connection_id.data(), sync_token.data(), smd.counter);

        smd.counter--;

        smd.actions.emplace_back(action);

        if (!smd.counter) {
            DBG("run multi-event finalization actions");
            for (auto &action : smd.actions) {
                action.perform();
            }
            connection_id = sync_token;
            sync_multies.erase(sync_token);
        }
        return true;
    }
    return false;
}

void HttpClient::sendRpcResponse(RpcRequestsMap::iterator &it, const AmArg &ret)
{
    postJsonRpcReply(it->second, ret);
    rpc_requests.erase(it);
}

void HttpClient::on_trigger_sync_context(const HttpTriggerSyncContext &e)
{
    auto it = sync_contexts.find(e.sync_ctx_id);
    if (it == sync_contexts.end()) {
        if (HttpClient::events_log_level >= 0) {
            _LOG(HttpClient::events_log_level, "on_trigger_sync_context: no context '%s'. create new with counter %d",
                 e.sync_ctx_id.c_str(), -e.quantity);
        }
        sync_contexts.emplace(e.sync_ctx_id, -e.quantity);
        return;
    }

    if (HttpClient::events_log_level >= 0) {
        _LOG(HttpClient::events_log_level,
             "on_trigger_sync_context: found context %s. counter %d. requeue postponed events and decrease counter by "
             "%d",
             e.sync_ctx_id.c_str(), it->second.counter, e.quantity);
    }
    it->second.counter -= e.quantity;

    auto &postponed_events = it->second.postponed_events;
    while (!postponed_events.empty()) {
        process_http_event(postponed_events.front());
        delete postponed_events.front();
        postponed_events.pop();
    }

    if (it->second.counter < 0) {
        if (HttpClient::events_log_level >= 0) {
            _LOG(HttpClient::events_log_level, "on_trigger_sync_context: finished. context %s. counter %d",
                 e.sync_ctx_id.c_str(), it->second.counter);
        }
        return;
    }

    if (it->second.counter > 0) {
        ERROR("on_trigger_sync_context: more than expected send events for syncronization context %s. "
              "remove it anyway. ",
              e.sync_ctx_id.c_str());
    }

    if (HttpClient::events_log_level >= 0) {
        _LOG(HttpClient::events_log_level, "on_trigger_sync_context: remove context %s", e.sync_ctx_id.c_str());
    }

    sync_contexts.erase(it);
}

void HttpClient::on_sync_context_timer()
{
    sync_contexts_timer.read();
    time_t now = time(nullptr);
    for (auto it = sync_contexts.begin(); it != sync_contexts.end();) {
        if (now - it->second.created_at > SYNC_CONTEXTS_TIMEOUT_INVERVAL) {
            auto &postponed_events = it->second.postponed_events;
            if (!postponed_events.empty()) {
                ERROR("remove context %s on timeout, counter: %d. requeue %ld postponed events", it->first.c_str(),
                      it->second.counter, postponed_events.size());

                while (!postponed_events.empty()) {
                    process_http_event(postponed_events.front());
                    delete postponed_events.front();
                    postponed_events.pop();
                }
            } else {
                if (HttpClient::events_log_level >= 0) {
                    _LOG(HttpClient::events_log_level, "remove context %s on timeout, counter: %d", it->first.c_str(),
                         it->second.counter);
                }
            }

            it = sync_contexts.erase(it);

        } else {
            ++it;
        }
    }
}

void HttpClient::on_upload_request(HttpUploadEvent *u)
{
    HttpDestinationsMap::iterator destination = destinations.find(u->destination_name);
    if (destination == destinations.end()) {
        ERROR("event with unknown destination '%s' from session %s. ignore it", u->destination_name.c_str(),
              u->session_id.c_str());
        on_init_connection_error(u->sync_ctx_id);
        return;
    }

    HttpDestination &d = destination->second;
    if (d.mode != HttpDestination::Put) {
        ERROR("wrong destination '%s' type for upload request from session %s. 'put' mode expected. ignore it",
              u->destination_name.c_str(), u->session_id.c_str());
        return;
    }

    if (HttpClient::events_log_level >= 0) {
        if (u->token.empty()) {
            _LOG(HttpClient::events_log_level, "[%s/%s] http upload request: %s => %s [%i/%i]", u->session_id.data(),
                 u->sync_ctx_id.data(), u->file_path.c_str(), d.url[u->failover_idx].c_str(), u->failover_idx,
                 u->attempt);
        } else {
            _LOG(HttpClient::events_log_level, "[%s/%s] http upload request: %s => %s [%i/%i] token: %s",
                 u->session_id.data(), u->sync_ctx_id.data(), u->file_path.c_str(), d.url[u->failover_idx].c_str(),
                 u->failover_idx, u->attempt, u->token.c_str());
        }
    }

    if (check_http_event_sync_ctx(*u)) {
        if (HttpClient::events_log_level >= 0) {
            _LOG(HttpClient::events_log_level, "http upload request is consumed by synchronization contexts handler %s",
                 u->sync_ctx_id.data());
        }
        return;
    }

    if (!u->attempt && d.count_connection.get() >= d.connection_limit) {
        if (HttpClient::events_log_level >= 0) {
            _LOG(HttpClient::events_log_level, "[%s/%s] http upload request marked as postponed", u->session_id.data(),
                 u->sync_ctx_id.data());
        }
        d.addEvent(new HttpUploadEvent(*u));
        return;
    }

    authorization(d, u);

    HttpUploadConnection *c = new HttpUploadConnection(d, *u, u->sync_ctx_id);
    if (c->init(hosts, curl_multi)) {
        ERROR("[%s/%s] http upload connection intialization error", u->session_id.data(), u->sync_ctx_id.data());
        u->attempt ? d.resend_count_connection.dec() : d.count_connection.dec();
        on_init_connection_error(u->sync_ctx_id);
        delete c;
    }
}

void HttpClient::authorization(HttpDestination &d, HttpEvent *u)
{
    if (d.auth_required.empty())
        return;

    HttpAuthsMap::iterator it = auths.find(d.auth_required);

    if (it == auths.end())
        return;

    auto auth = it->second;

    switch (auth->auth_type) {
    case HttpDestination::AuthType::AuthType_Firebase_oauth2:
        if (auth->access_token.empty())
            return;

        u->headers.emplace("Authorization", "Bearer " + auth->access_token);
        break;

    case HttpDestination::AuthType::AuthType_s3:
        if (auth->access_key.empty() || auth->secret_key.empty())
            return;

        if (auto upload_event = dynamic_cast<HttpUploadEvent *>(u)) {
            if (upload_event->file_name.empty()) {
                upload_event->file_name = filename_from_fullpath(upload_event->file_path);
            }

            auto resource = get_url_resource(d.url[upload_event->failover_idx] + '/' + upload_event->file_name);
            if (!resource)
                return;

            string date(get_rfc5322_date_str());

            string sig_str;
            sig_str.reserve(256);

            sig_str += "PUT\n\n";
            sig_str += d.content_type;
            sig_str += '\n';
            sig_str += date;
            sig_str += '\n';
            sig_str += *resource;

            // if failover happens renew headers (e.g. 'resource' or 'date' can be changed)
            upload_event->headers.erase("Authorization");
            upload_event->headers.erase("Date");

            upload_event->headers.emplace("Authorization", "AWS " + auth->access_key + ':' +
                                                               compute_hmac_sha1(sig_str, auth->secret_key));
            upload_event->headers.emplace("Date", date);
        }

        break;

    default:;
    }
}

void HttpClient::on_post_request(HttpPostEvent *u)
{
    HttpDestinationsMap::iterator destination = destinations.find(u->destination_name);
    if (destination == destinations.end()) {
        ERROR("event with unknown destination '%s' from session %s. ignore it", u->destination_name.c_str(),
              u->session_id.c_str());
        on_init_connection_error(u->sync_ctx_id);
        return;
    }

    HttpDestination &d = destination->second;
    if (d.mode != HttpDestination::Post) {
        ERROR("wrong destination '%s' mode for upload request from session %s. 'post' mode expected. ignore it",
              u->destination_name.c_str(), u->session_id.c_str());
        return;
    }

    authorization(d, u);

    if (HttpClient::events_log_level >= 0) {
        if (u->token.empty()) {
            _LOG(HttpClient::events_log_level, "[%s/%s] http post request url: %s [%i/%i]", u->session_id.data(),
                 u->sync_ctx_id.data(), d.url[u->failover_idx].c_str(), u->failover_idx, u->attempt);
        } else {
            _LOG(HttpClient::events_log_level, "[%s/%s] http post request url: %s [%i/%i], token: %s",
                 u->session_id.data(), u->sync_ctx_id.data(), d.url[u->failover_idx].c_str(), u->failover_idx,
                 u->attempt, u->token.c_str());
        }
    }

    if (check_http_event_sync_ctx(*u)) {
        if (HttpClient::events_log_level >= 0) {
            _LOG(HttpClient::events_log_level, "http post request is consumed by synchronization contexts handler %s",
                 u->sync_ctx_id.data());
        }
        return;
    }

    if (!u->attempt && d.count_connection.get() == d.connection_limit) {
        if (HttpClient::events_log_level >= 0) {
            _LOG(HttpClient::events_log_level, "[%s/%s] http post request marked as postponed", u->session_id.data(),
                 u->sync_ctx_id.data());
        }
        d.addEvent(new HttpPostEvent(*u));
        return;
    }

    HttpPostConnection *c = new HttpPostConnection(d, *u, u->sync_ctx_id);
    if (c->init(hosts, curl_multi)) {
        ERROR("[%s/%s] http post connection intialization error", u->session_id.data(), u->sync_ctx_id.data());
        u->attempt ? d.resend_count_connection.dec() : d.count_connection.dec();
        on_init_connection_error(u->sync_ctx_id);
        delete c;
    }
}

void HttpClient::on_multpart_form_request(HttpPostMultipartFormEvent *u)
{
    HttpDestinationsMap::iterator destination = destinations.find(u->destination_name);
    if (destination == destinations.end()) {
        ERROR("event with unknown destination '%s' from session %s. ignore it", u->destination_name.c_str(),
              u->session_id.c_str());
        on_init_connection_error(u->sync_ctx_id);
        return;
    }

    HttpDestination &d = destination->second;
    if (d.mode != HttpDestination::Post) {
        ERROR("wrong destination '%s' mode for upload request from session %s. 'post' mode expected. ignore it",
              u->destination_name.c_str(), u->session_id.c_str());
        return;
    }

    if (HttpClient::events_log_level >= 0) {
        if (u->token.empty()) {
            _LOG(HttpClient::events_log_level, "[%s/%s] http multipart form request url: %s [%i/%i]",
                 u->session_id.data(), u->sync_ctx_id.data(), d.url[u->failover_idx].c_str(), u->failover_idx,
                 u->attempt);
        } else {
            _LOG(HttpClient::events_log_level, "[%s/%s] http multipart form request url: %s [%i/%i], token: %s",
                 u->session_id.data(), u->sync_ctx_id.data(), d.url[u->failover_idx].c_str(), u->failover_idx,
                 u->attempt, u->token.c_str());
        }
    }

    if (check_http_event_sync_ctx(*u)) {
        if (HttpClient::events_log_level >= 0) {
            _LOG(HttpClient::events_log_level,
                 "multipart form request is consumed by synchronization contexts handler %s", u->sync_ctx_id.data());
        }
        return;
    }

    if (!u->attempt && d.count_connection.get() == d.connection_limit) {
        if (HttpClient::events_log_level >= 0) {
            _LOG(HttpClient::events_log_level, "[%s/%s] http multipart form request marked as postponed",
                 u->session_id.data(), u->sync_ctx_id.data());
        }
        d.addEvent(new HttpPostMultipartFormEvent(*u));
        return;
    }

    authorization(d, u);

    HttpMultiPartFormConnection *c = new HttpMultiPartFormConnection(d, *u, u->sync_ctx_id);
    if (c->init(hosts, curl_multi)) {
        ERROR("[%s/%s] http multipart form connection intialization error", u->session_id.data(),
              u->sync_ctx_id.data());
        u->attempt ? d.resend_count_connection.dec() : d.count_connection.dec();
        on_init_connection_error(u->sync_ctx_id);
        delete c;
    }
}

void HttpClient::on_get_request(HttpGetEvent *e)
{
    HttpDestinationsMap::iterator destination = destinations.find(e->destination_name);
    if (destination == destinations.end()) {
        ERROR("event with unknown destination '%s' from session %s. ignore it", e->destination_name.c_str(),
              e->session_id.c_str());
        on_init_connection_error(e->sync_ctx_id);
        return;
    }

    HttpDestination &d = destination->second;
    if (d.mode != HttpDestination::Get) {
        ERROR("wrong destination '%s' mode for request from session %s. 'get' mode expected. ignore it",
              e->destination_name.c_str(), e->session_id.c_str());
        return;
    }

    if (HttpClient::events_log_level >= 0) {
        if (e->token.empty()) {
            _LOG(HttpClient::events_log_level, "[%s/%s] http get request url: %s [%i/%i]", e->session_id.data(),
                 e->sync_ctx_id.data(), e->url.c_str(), e->failover_idx, e->attempt);
        } else {
            _LOG(HttpClient::events_log_level, "[%s/%s] http get request url: %s [%i/%i], token: %s",
                 e->session_id.data(), e->sync_ctx_id.data(), e->url.c_str(), e->failover_idx, e->attempt,
                 e->token.c_str());
        }
    }

    if (!e->attempt && d.count_connection.get() == d.connection_limit) {
        if (HttpClient::events_log_level >= 0) {
            _LOG(HttpClient::events_log_level, "[%s/%s] http get request marked as postponed", e->session_id.data(),
                 e->sync_ctx_id.data());
        }
        d.addEvent(new HttpGetEvent(*e));
        return;
    }

    authorization(d, e);

    HttpGetConnection *c = new HttpGetConnection(d, *e, e->sync_ctx_id, epoll_fd);
    if (c->init(hosts, curl_multi)) {
        ERROR("[%s/%s] http get connection intialization error", e->session_id.data(), e->sync_ctx_id.data());
        e->attempt ? d.resend_count_connection.dec() : d.count_connection.dec();
        on_init_connection_error(e->sync_ctx_id);
        delete c;
    }
}

void HttpClient::on_init_connection_error(const string &conn_id)
{
    string connection_id = conn_id;
    bool   success       = checkMultiResponse(DestinationAction(), connection_id);

    auto it = rpc_requests.find(connection_id);
    if (it != rpc_requests.end()) {
        AmArg ret;
        ret["result"] = success ? "finished" : "failed";
        sendRpcResponse(it, ret);
    }
}

void HttpClient::on_multi_request(HttpMultiEvent *e)
{
    if (check_http_event_sync_ctx(*e)) {
        if (HttpClient::events_log_level >= 0) {
            _LOG(HttpClient::events_log_level,
                 "[%s/%s] http multi request is consumed by synchronization contexts handler %s", e->session_id.data(),
                 e->sync_ctx_id.data(), e->sync_ctx_id.data());
        }
        return;
    }

    string sync_token = e->sync_ctx_id.empty() ? AmSession::getNewId() : e->sync_ctx_id;
    int    count      = 0;
    for (auto &ev : e->multi_events) {
        ev->sync_ctx_id = ev->sync_ctx_id.empty() ? AmSession::getNewId() : ev->sync_ctx_id;
        multi_data_entries.try_emplace(ev->sync_ctx_id, sync_token, ev->token, ev->session_id);
        count++;
        if (ev->event_id < HttpEvent::Get) {
            // Upload, Post, MultiPartForm
            sync_contexts.emplace(ev->sync_ctx_id, -1);
        }
        postEvent(ev.release());
    }
    sync_multies.emplace(sync_token, count);
}

void HttpClient::on_auth_timer()
{
    auth_timer.read();

    for (auto &[name, auth] : auths)
        auth->auth_on_timer_event(this, name);
}

void HttpClient::on_resend_timer_event()
{
    resend_timer.read();

    for (auto &dest : destinations) {
        dest.second.send_failed_events(this);
    }
}

static bool add_to_resolve_slist(struct curl_slist **hosts, const char *r_host)
{
    struct curl_slist *host       = *hosts;
    int                r_host_len = strlen(r_host);
    while (host) {
        int host_len = strlen(host->data);
        if (host_len == r_host_len && !strncmp(host->data, r_host, host_len))
            return true;
        host = host->next;
    }

    struct curl_slist *tmp = curl_slist_append(*hosts, r_host);
    if (!tmp) {
        curl_slist_free_all(*hosts);
        return false;
    }

    *hosts = tmp;
    return true;
}


void HttpClient::update_resolve_list()
{
    DBG("update local DNS cache");

    resolve_timer.read();

    if (hosts) {
        curl_slist_free_all(hosts);
        hosts = 0;
    }

    CURLU *curlu = curl_url();
    if (!curlu)
        return;
    uint64_t next_time = 0;

    for (auto &dst : destinations) {
        for (auto &url : dst.second.url) {
            char            *host = 0;
            char            *port = 0;
            dns_handle       handle;
            sockaddr_storage sa;

            if (curl_url_set(curlu, CURLUPART_URL, url.c_str(), 0))
                continue;
            curl_url_get(curlu, CURLUPART_HOST, &host, 0);
            curl_url_get(curlu, CURLUPART_PORT, &port, 0);

            if (resolver::instance()->resolve_name(host, &handle, &sa, Dualstack) <= 0) {
                curl_free(host);
                if (port)
                    curl_free(port);
                continue;
            }

            if (!next_time || next_time > handle.get_expired()) {
                next_time = handle.get_expired();
            }

            std::string rhost;
            rhost.append(host);
            rhost.append(":");
            if (port)
                rhost.append(port);
            else
                rhost.append("80");
            rhost.append(":");

            rhost.append(am_inet_ntop(&sa));
            while (handle.next_ip(&sa, Dualstack) != -1) {
                rhost.append(",");
                rhost.append(am_inet_ntop(&sa));
            }

            curl_free(host);
            if (port)
                curl_free(port);

            add_to_resolve_slist(&hosts, rhost.c_str());
        }
    }
    curl_url_cleanup(curlu);

    if (next_time)
        DBG3("set resolve_timer interval to: %f sec", next_time / 1e6);
    else
        DBG3("disarm resolve_timer");

    resolve_timer.set(next_time);
}

void HttpClient::on_connection_delete(CurlConnection *c)
{
    string connection_id = c->get_connection_id();
    bool   is_multi      = c->is_requeue() ? false : checkMultiResponse(c->get_action(), connection_id);
    AmArg  ret;

    if (!is_multi)
        c->run_action();

    auto it = rpc_requests.find(connection_id);
    if (it != rpc_requests.end()) {
        AmArg ret;

        if (is_multi)
            ret["result"] = "finished";
        else
            c->get_response(ret);

        sendRpcResponse(it, ret);
    }

    for (auto &dest : destinations) {
        dest.second.send_postponed_events(this);
    }
    checkFinished();
}

void HttpClient::showStats(const AmArg &, AmArg &ret)
{
    ret["resend_interval"]    = resend_interval;
    ret["sync_context_count"] = sync_contexts.size();
    for (auto &dest : destinations) {
        AmArg &dst_arr = ret["destinations"];
        AmArg &dst     = dst_arr[dest.first.c_str()];
        dest.second.showStats(dst);
    }
}

uint64_t HttpClient::get_active_tasks_count()
{
    uint64_t tasks = 0;

    tasks += sync_contexts.size();

    m_queue.lock();
    tasks += ev_queue.size();
    m_queue.unlock();

    for (const auto &i : destinations) {
        auto &dest = i.second;
        tasks += dest.events.size();
        tasks += dest.count_connection.get();
        // FIXME: should we ensure a graceful shutdown for retransmits ?
        tasks += dest.resend_count_connection.get();
    }

    return tasks;
}

static std::optional<string> get_url_resource(const string &url)
{
    CURLU *h = curl_url();
    if (CURLUE_OK != curl_url_set(h, CURLUPART_URL, url.data(), 0)) {
        curl_url_cleanup(h);
        return std::nullopt;
    }

    char *path;
    if (CURLUE_OK != curl_url_get(h, CURLUPART_PATH, &path, 0)) {
        curl_url_cleanup(h);
        return std::nullopt;
    }

    string ret(path);

    curl_free(path);
    curl_url_cleanup(h);

    return ret;
}

static string get_rfc5322_date_str()
{
    auto      t = std::time(nullptr);
    struct tm tt;
    localtime_r(&t, &tt);
    char s[64] = { 0 };
    int  len   = strftime(s, sizeof s, "%a, %d %b %Y %X %z", &tt);
    if (len <= 0)
        return string();
    return string(s, len);
}


static string compute_hmac_sha1(const string &msg, const string &key)
{
    Botan::secure_vector<uint8_t> sec_key(key.begin(), key.end());
    auto                          hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-1)");
    hmac->set_key(sec_key);
    hmac->update(msg);
    return Botan::base64_encode(hmac->final());
}

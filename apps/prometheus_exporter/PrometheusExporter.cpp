#include "PrometheusExporter.h"
#include "prometheus_exporter_cfg.h"
#include "AmStatisticsCounter.h"

#define MOD_NAME "prometheus_exporter"

class PrometheusExporterFactory
    : public AmConfigFactory
{
    PrometheusExporterFactory(const string& name)
      : AmConfigFactory(name)
    {
        PrometheusExporter::instance();
    }
    ~PrometheusExporterFactory()
    {
        DBG("~PrometheusExporterFactory");
        PrometheusExporter::dispose();
    }
  public:
    DECLARE_FACTORY_INSTANCE(PrometheusExporterFactory);

    int configure(const string& config)
    {
        return PrometheusExporter::instance()->configure(config);
    }

    int onLoad()
    {
        return PrometheusExporter::instance()->onLoad();
    }
    void on_destroy() {
        PrometheusExporter::instance()->stop();
    }
};

EXPORT_PLUGIN_CONF_FACTORY(PrometheusExporterFactory);
DEFINE_FACTORY_INSTANCE(PrometheusExporterFactory, MOD_NAME);

PrometheusExporter* PrometheusExporter::_instance=0;

PrometheusExporter* PrometheusExporter::instance()
{
    if(_instance == NULL){
        _instance = new PrometheusExporter();
    }
    return _instance;
}

void PrometheusExporter::dispose()
{
    if(_instance != NULL){
        delete _instance;
    }
    _instance = NULL;
}

int label_func(cfg_t *cfg, cfg_opt_t *opt, int argc, const char **argv)
{
    if(argc != 2) {
        cfg_error(cfg, "label must have 2 arguments");
        return 1;
    }
    std::string option, value;
    switch(argc)
    {
    case 0:
        return 1;
    case 2:
        value = argv[1];
    case 1:
        option = argv[0];
        break;
    }

    statistics::instance()->AddLabel(option, value);
    return 0;
}

int validate_method_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    bool valid = (value == VALUE_DROP || value == VALUE_REJECT);
    if(!valid) {
        ERROR("invalid value \'%s\' of option \'%s\' - must be \'drop\' or \'reject\'", value.c_str(), opt->name);
    }
    return valid ? 0 : 1;
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

PrometheusExporter::PrometheusExporter()
    : ev_base(0), ev_http(0){}

PrometheusExporter::~PrometheusExporter()
{
    if(ev_http) evhttp_free(ev_http);
}

void PrometheusExporter::status_request_cb(struct evhttp_request* req)
{
    struct evhttp_connection* conn = evhttp_request_get_connection(req);
    char* addr;
    ev_uint16_t port;
    evhttp_connection_get_peer(conn, &addr, &port);
    struct sockaddr_storage dst;
    am_inet_pton(addr, &dst);
    trsp_acl::action_t acl_action = acl.check(dst);
    switch(acl_action) {
    case trsp_acl::Allow:
        break;
    case trsp_acl::Drop:
    {
        DBG("message dropped by interface ACL %s:%d", addr, port);
        evhttp_connection_free(conn);
        return;
    }
    case trsp_acl::Reject:
        DBG("message rejected by interface ACL %s:%d", addr, port);
        evhttp_send_reply_start(req, 403, "Forbidden");
        evhttp_send_reply_end(req);
        return;
    }

    evhttp_add_header(evhttp_request_get_output_headers(req),
                      "Content-Type","text/plain");
    evbuffer *buf = evbuffer_new();
    vector<StatCounter*> counters = statistics::instance()->GetCounters();
    struct timeval tv;
    gettimeofday(&tv, 0);
    unsigned long long timet = tv.tv_sec*1000 + tv.tv_usec/1000;
    for(auto counter : counters) {
        string type = counter->type_str();
        string name = counter->name();
        unsigned long long cnt;
        counter->get(&cnt);
        if(!counter->getHelp().empty()) {
            evbuffer_add_printf(buf, "#HELP %s_%s %s\n", prefix.c_str(), name.c_str(), counter->getHelp().c_str());
        }
        if(statistics::instance()->GetLabels().empty() && counter->getLabels().empty()) {
            evbuffer_add_printf(buf, "#TYPE %s_%s %s\n%s_%s %llu %llu\n", prefix.c_str(), name.c_str(), type.c_str(), prefix.c_str(), name.c_str(), cnt, timet);
        } else {
            evbuffer_add_printf(buf, "#TYPE %s_%s %s\n%s_%s{", prefix.c_str(), name.c_str(), type.c_str(), prefix.c_str(), name.c_str());
            auto labels = statistics::instance()->GetLabels(counter->getLabels());
            for(auto label = labels.begin(); label != labels.end(); label++) {
                if(label != labels.begin())
                    evbuffer_add_printf(buf, ", ");
                evbuffer_add_printf(buf, "%s=\"%s\"", label->first.c_str(), label->second.c_str());
            }
            evbuffer_add_printf(buf, "} %llu %llu\n", cnt, timet);
        }
    }
    evhttp_send_reply_start(req, HTTP_OK, "OK");
    evhttp_send_reply_chunk(req,buf);
    evhttp_send_reply_end(req);
    evbuffer_free(buf);
}

int PrometheusExporter::configure(const string& config)
{
    cfg_t *cfg = cfg_init(prometheus_exporter_opt, CFGF_NONE);
    cfg_set_validate_func(cfg, PARAM_METHOD, validate_method_func);
    if(!cfg) return -1;
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

    ip = cfg_getstr(cfg, PARAM_ADDRESS);
    port = cfg_getint(cfg, PARAM_PORT);
    prefix = cfg_getstr(cfg, PARAM_PREFIX);
    if(cfg_size(cfg, SECTION_ACL)) {
        cfg_t* cfg_acl = cfg_getsec(cfg, SECTION_ACL);
        if(readAcl(cfg_acl)) return -1;
    }

    cfg_free(cfg);
    return 0;
}

int PrometheusExporter::readAcl(cfg_t* cfg)
{
    int networks = 0;
    for(unsigned int j = 0; j < cfg_size(cfg, PARAM_WHITELIST); j++) {
        AmSubnet net;
        std::string host = cfg_getnstr(cfg, PARAM_WHITELIST, j);
        if(!net.parse(host)) {
            return 1;
        }
        acl.add_network(net);
        networks++;
    }

    DBG("parsed %d networks %s",networks);

    std::string method = cfg_getstr(cfg, PARAM_METHOD);
    if(method == "drop"){
        acl.set_action(trsp_acl::Drop);
    } else if(method == "reject") {
        acl.set_action(trsp_acl::Reject);
    } else {
        ERROR("unknown acl method '%s'", method.c_str());
        return 1;
    }

    return 0;
}

int PrometheusExporter::init()
{
    ev_base = event_base_new();
    if (!ev_base) {
        ERROR("couldn't create an event_base");
        return -1;
    }

    ev_http = evhttp_new(ev_base);
    if (!ev_http) {
        ERROR("couldn't create evhttp");
        return -1;
    }

    evhttp_set_allowed_methods(ev_http, EVHTTP_REQ_GET | EVHTTP_REQ_POST | EVHTTP_REQ_HEAD);
    evhttp_set_cb(ev_http, "/metrics",
                  [](struct evhttp_request *req, void *arg) {
                      static_cast<PrometheusExporter*>(arg)->status_request_cb(req);
                  }, this);

    struct evhttp_bound_socket *ev_http_handle = evhttp_bind_socket_with_handle(ev_http, ip.c_str(), port);
    if(!ev_http_handle) {
        ERROR("couldn't bind http server to %s:%d",ip.c_str(),port);
        return -1;
    }

    DBG("prometeus exporter bind socket to: %s:%d",ip.c_str(),port);

    int flags = EFD_NONBLOCK | EFD_SEMAPHORE;
    int event_fd;
    if((event_fd = eventfd(0, flags)) == -1) {
        ERROR("failed to create eventfd");
        return -1;
    }

    return 0;
}

int PrometheusExporter::onLoad()
{
    if(init()){
        ERROR("initialization error");
        return -1;
    }
    start();
    return 0;
}

void PrometheusExporter::run()
{
    INFO("prometheus exporter server thread\n");
    setThreadName("prometheus-exporter");
    event_base_dispatch(ev_base);
    INFO("prometheus exporter server finished");
}

void PrometheusExporter::on_stop()
{
    event_base_loopexit(ev_base, NULL);
}

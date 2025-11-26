#include "PrometheusExporter.h"
#include "prometheus_exporter_cfg.h"
#include "AmStatistics.h"
#include "sip/wheeltimer.h"

#define MOD_NAME "prometheus_exporter"

class PrometheusExporterFactory : public AmConfigFactory {
    PrometheusExporterFactory(const string &name)
        : AmConfigFactory(name)
    {
        PrometheusExporter::instance();
    }
    ~PrometheusExporterFactory() override
    {
        DBG("~PrometheusExporterFactory");
        PrometheusExporter::dispose();
    }

  public:
    DECLARE_FACTORY_INSTANCE(PrometheusExporterFactory)

    int configure(const string &config) override { return PrometheusExporter::instance()->configure(config); }

    int reconfigure(const std::string &config) override { return 0; }

    int onLoad() override { return PrometheusExporter::instance()->onLoad(); }

    void onShutdown() override { PrometheusExporter::instance()->stop(true); }
};

EXPORT_PLUGIN_CONF_FACTORY(PrometheusExporterFactory);
DEFINE_FACTORY_INSTANCE(PrometheusExporterFactory, MOD_NAME);

PrometheusExporter *PrometheusExporter::_instance = nullptr;

PrometheusExporter *PrometheusExporter::instance()
{
    if (_instance == nullptr) {
        _instance = new PrometheusExporter();
    }
    return _instance;
}

void PrometheusExporter::dispose()
{
    if (_instance != nullptr) {
        delete _instance;
    }
    _instance = nullptr;
}

int label_func(cfg_t *cfg, cfg_opt_t *, int argc, const char **argv)
{
    if (argc != 2) {
        cfg_error(cfg, "label must have 2 arguments");
        return 1;
    }
    std::string option, value;
    switch (argc) {
    case 0: return 1;
    case 2:
        value = argv[1];
        /* fall through */
    case 1: option = argv[0]; break;
    }

    statistics::instance()->addLabel(option, value);

    return 0;
}

int validate_method_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    bool        valid = (value == VALUE_DROP || value == VALUE_REJECT);
    if (!valid) {
        ERROR("invalid value \'%s\' of option \'%s\' - must be \'drop\' or \'reject\'", value.c_str(), opt->name);
    }
    return valid ? 0 : 1;
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

PrometheusExporter::PrometheusExporter()
    : ev_base(nullptr)
    , ev_http(nullptr)
{
}

PrometheusExporter::~PrometheusExporter()
{
    if (ev_http)
        evhttp_free(ev_http);
    if (ev_base)
        event_base_free(ev_base);
}

inline void serialize_label(evbuffer *buf, const map<string, string>::value_type &label, bool &begin)
{
    if (!begin) {
        evbuffer_add_printf(buf, ", ");
    } else {
        begin = false;
    }

    evbuffer_add_printf(buf, "%s=\"%s\"", label.first.c_str(), label.second.c_str());
}

void PrometheusExporter::status_request_cb(struct evhttp_request *req)
{
    struct evhttp_connection *conn = evhttp_request_get_connection(req);
    char                     *addr;
    ev_uint16_t               port;

    evhttp_connection_get_peer(conn, &addr, &port);
    struct sockaddr_storage dst;
    am_inet_pton(addr, &dst);

    trsp_acl::action_t acl_action = acl.check(dst);
    switch (acl_action) {
    case trsp_acl::Allow: break;
    case trsp_acl::Drop:
        DBG("message dropped by interface ACL %s:%d", addr, port);
        evhttp_connection_free(conn);
        return;
    case trsp_acl::Reject:
        DBG("message rejected by interface ACL %s:%d", addr, port);
        evhttp_send_reply_start(req, 403, "Forbidden");
        evhttp_send_reply_end(req);
        return;
    }

    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "text/plain; version=0.0.4");

    evbuffer *buf = evbuffer_new();
    // auto now = wheeltimer::instance()->unix_ms_clock.get();

    statistics::instance()->iterate_groups(
        [this, /*&now,*/ buf](const std::string &name, StatCountersGroupsInterface &group) {
            auto type = StatCountersGroupsInterface::type2str(group.getType());

            evbuffer_add_printf(buf, "# TYPE %s_%s %s\n", prefix.c_str(), name.data(), type);
            if (!group.getHelp().empty()) {
                evbuffer_add_printf(buf, "# HELP %s_%s %s\n", prefix.c_str(), name.data(), group.getHelp().data());
            }

            group.iterate_counters([this, &name, /*&now,*/ buf](unsigned long long value,
                                                                /*unsigned long long timet,*/
                                                                const map<string, string> &counter_labels) {
                // auto &timestamp = timet ? timet : now;
                // bool &omit_timestamp = timet ? omit_update_timestamp : omit_now_timestamp;
                auto &common_labels = statistics::instance()->getLabelsUnsafe();

                if (common_labels.empty() && counter_labels.empty()) {
                    // if(omit_timestamp) {
                    evbuffer_add_printf(buf, "%s_%s %llu\n", prefix.c_str(), name.c_str(), value);
                    /*} else {
                        evbuffer_add_printf(buf, "%s_%s %llu %llu\n",
                            prefix.c_str(), name.c_str(),
                            value, timestamp);
                    }*/
                } else {
                    evbuffer_add_printf(buf, "%s_%s{", prefix.c_str(), name.c_str());

                    bool begin = true;
                    for (const auto &l : common_labels)
                        serialize_label(buf, l, begin);
                    for (const auto &l : counter_labels)
                        serialize_label(buf, l, begin);

                    // if(omit_timestamp) {
                    evbuffer_add_printf(buf, "} %llu\n", value);
                    /*} else {
                        evbuffer_add_printf(buf, "} %llu %llu\n",
                            value, timestamp);
                    }*/
                }
            });
        });

    evhttp_send_reply_start(req, HTTP_OK, "OK");
    evhttp_send_reply_chunk(req, buf);
    evhttp_send_reply_end(req);
    evbuffer_free(buf);
}

int PrometheusExporter::configure(const string &config)
{
    char  *s;
    cfg_t *cfg = cfg_init(prometheus_exporter_opt, CFGF_NONE);
    if (!cfg)
        return -1;

    cfg_set_validate_func(cfg, PARAM_METHOD, validate_method_func);
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

    s = cfg_getstr(cfg, PARAM_ADDRESS);
    if (!s) {
        ERROR("missed mandatory option: %s", PARAM_ADDRESS);
        return -1;
    }
    ip     = cfg_getstr(cfg, PARAM_ADDRESS);
    port   = static_cast<decltype(port)>(cfg_getint(cfg, PARAM_PORT));
    prefix = cfg_getstr(cfg, PARAM_PREFIX);
    // omit_now_timestamp = cfg_getbool(cfg, PARAM_OMIT_NOW_TIMESTAMP);
    // omit_update_timestamp = cfg_getbool(cfg, PARAM_OMIT_UPDATE_TIMESTAMP);
    if (cfg_size(cfg, SECTION_ACL)) {
        cfg_t *cfg_acl = cfg_getsec(cfg, SECTION_ACL);
        if (readAcl(cfg_acl))
            return -1;
    }

    cfg_free(cfg);
    return 0;
}

int PrometheusExporter::readAcl(cfg_t *cfg)
{
    int networks = 0;
    for (unsigned int j = 0; j < cfg_size(cfg, PARAM_WHITELIST); j++) {
        AmSubnet    net;
        std::string host = cfg_getnstr(cfg, PARAM_WHITELIST, j);
        if (!net.parse(host)) {
            return 1;
        }
        acl.add_network(net);
        networks++;
    }

    DBG("parsed %d networks", networks);

    std::string method = cfg_getstr(cfg, PARAM_METHOD);
    if (method == "drop") {
        acl.set_action(trsp_acl::Drop);
    } else if (method == "reject") {
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
    evhttp_set_cb(
        ev_http, "/metrics",
        [](struct evhttp_request *req, void *arg) { static_cast<PrometheusExporter *>(arg)->status_request_cb(req); },
        this);

    struct evhttp_bound_socket *ev_http_handle = evhttp_bind_socket_with_handle(ev_http, ip.c_str(), port);
    if (!ev_http_handle) {
        ERROR("couldn't bind http server to %s:%d", ip.c_str(), port);
        return -1;
    }

    DBG("prometeus exporter bind socket to: %s:%d", ip.c_str(), port);

    int flags = EFD_NONBLOCK | EFD_SEMAPHORE;
    int event_fd;
    if ((event_fd = eventfd(0, flags)) == -1) {
        ERROR("failed to create eventfd");
        return -1;
    }

    return 0;
}

int PrometheusExporter::onLoad()
{
    if (init()) {
        ERROR("initialization error");
        return -1;
    }
    start();
    return 0;
}

void PrometheusExporter::run()
{
    setThreadName("prometheus-http");
    event_base_dispatch(ev_base);
}

void PrometheusExporter::on_stop()
{
    event_base_loopbreak(ev_base);
}

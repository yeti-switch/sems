#pragma once

#include "AmApi.h"

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <confuse.h>

#include <string>
using std::string;

class PrometheusExporter : public AmThread {
    friend class PrometheusExporterFactory;
    static PrometheusExporter *_instance;

    string   ip;
    uint16_t port;
    string   prefix;
    // bool omit_now_timestamp;
    // bool omit_update_timestamp;
    trsp_acl acl;

    struct event_base *ev_base;
    struct evhttp     *ev_http;

    void status_request_cb(struct evhttp_request *req);

    int configure(const string &config);
    int readAcl(cfg_t *cfg);

  public:
    PrometheusExporter();
    ~PrometheusExporter();

    static PrometheusExporter *instance();
    static void                dispose();

    int onLoad();
    int init();

    void run();
    void on_stop();
};

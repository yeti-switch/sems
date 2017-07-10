#include "HttpClient.h"

#include "log.h"

#include "AmSessionContainer.h"
#include "AmUtils.h"

#define MOD_NAME "http_client"

#include <vector>
using std::vector;

#define DEFAULT_RESEND_INTERVAL 5000 //milliseconds
#define DEFAULT_RESEND_QUEUE_MAX 10000

EXPORT_PLUGIN_CLASS_FACTORY(HttpClient, MOD_NAME);

HttpClient* HttpClient::_instance=0;

HttpClient* HttpClient::instance()
{
    if(_instance == NULL){
        _instance = new HttpClient(MOD_NAME);
    }
    return _instance;
}

HttpClient::HttpClient(const string& name)
  : AmDynInvokeFactory(name),
    AmEventFdQueue(this),
    epoll_fd(-1),
    stopped(false)
{
    _instance = this;
}

HttpClient::~HttpClient()
{}

int HttpClient::configure()
{
    AmConfigReader cfg;
    if(cfg.loadFile(AmConfig::ModConfigPath + string(MOD_NAME ".conf")))
        return -1;
    if(destinations.configure(cfg)){
        ERROR("can't configure destinations");
        return -1;
    }
    destinations.dump();

    resend_interval = cfg.getParameterInt("resend_interval",DEFAULT_RESEND_INTERVAL);
    resend_interval *= 1000;

    resend_queue_max = cfg.getParameterInt("resend_queue_max",DEFAULT_RESEND_QUEUE_MAX);

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

    if(init_curl(epoll_fd)){
        ERROR("curl init failed");
        return -1;
    }

    epoll_link(epoll_fd,true);
    stop_event.link(epoll_fd,true);

    DBG("HttpClient initialized");
    return 0;
}

int HttpClient::onLoad()
{
    if(configure()){
        ERROR("configuration error");
        return -1;
    }
    if(init()){
        ERROR("initialization error");
        return -1;
    }
    start();
    return 0;
}

void HttpClient::invoke(const string& method, const AmArg& args, AmArg& ret)
{
    if(method=="show"){
        destinations.dump(ret);
    } else if(method=="stats"){
        showStats(ret);
    } else if(method=="post") {
        postRequest(args,ret);
    } else if(method=="_list"){
        ret.push("stats");
        ret.push("post");
    } else {
        throw AmDynInvoke::NotImplemented(method);
    }
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

    while(!failed_upload_events.empty()){
        delete failed_upload_events.front();
        failed_upload_events.pop();
    }
    while(!failed_post_events.empty()){
        delete failed_post_events.front();
        failed_post_events.pop();
    }

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
    switch(ev->event_id){
    case E_SYSTEM: {
        AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(ev);
        if(sys_ev && sys_ev->sys_event == AmSystemEvent::ServerShutdown){
            stop_event.fire();
        }
    } break;
    case HttpEvent::Upload: {
        HttpUploadEvent *e = dynamic_cast<HttpUploadEvent*>(ev);
        if(e) on_upload_request(*e);
    } break;
    case HttpEvent::Post: {
        HttpPostEvent *e = dynamic_cast<HttpPostEvent*>(ev);
        if(e) on_post_request(*e);
    } break;
    default:
        WARN("unknown event received");
    }
}

void HttpClient::on_upload_request(const HttpUploadEvent &u)
{
    HttpDestinationsMap::const_iterator destination = destinations.find(u.destination_name);
    if(destination==destinations.end()){
        ERROR("event with unknown destination '%s' from session %s. ignore it",
            u.destination_name.c_str(),u.session_id.c_str());
        return;
    }

    const HttpDestination &d = destination->second;
    if(d.mode!=HttpDestination::Put) {
        ERROR("wrong destination '%s' type for upload request from session %s. 'put' mode expected. ignore it",
              u.destination_name.c_str(),u.session_id.c_str());
        return;
    }

    if(u.token.empty()){
        DBG("http upload request: %s => %s [%i/%i]",
            u.file_path.c_str(),
            d.url[u.failover_idx].c_str(),
            u.failover_idx,u.attempt);
    } else {
        DBG("http upload request: %s => %s [%i/%i] token: %s",
            u.file_path.c_str(),
            d.url[u.failover_idx].c_str(),
            u.failover_idx,u.attempt,
            u.token.c_str());
    }

    HttpUploadConnection *c = new HttpUploadConnection(u,d,epoll_fd);
    if(c->init(curl_multi)){
        ERROR("http upload connection intialization error");
        delete c;
    }
}

void HttpClient::on_post_request(const HttpPostEvent &u)
{
    HttpDestinationsMap::const_iterator destination = destinations.find(u.destination_name);
    if(destination==destinations.end()){
        ERROR("event with unknown destination '%s' from session %s. ignore it",
            u.destination_name.c_str(),u.session_id.c_str());
        return;
    }

    const HttpDestination &d = destination->second;
    if(d.mode!=HttpDestination::Post) {
        ERROR("wrong destination '%s' mode for upload request from session %s. 'post' mode expected. ignore it",
              u.destination_name.c_str(),u.session_id.c_str());
        return;
    }

    if(u.token.empty()){
        DBG("http post request url: %s [%i/%i]",
            d.url[u.failover_idx].c_str(),
            u.failover_idx,u.attempt);
    } else {
        DBG("http post request url: %s [%i/%i], token: %s",
            d.url[u.failover_idx].c_str(),
            u.failover_idx,u.attempt,
            u.token.c_str());
    }

    HttpPostConnection *c = new HttpPostConnection(u,d,epoll_fd);
    if(c->init(curl_multi)){
        ERROR("http post connection intialization error");
        delete c;
    }
}

void HttpClient::on_requeue(CurlConnection *c)
{
    HttpUploadConnection *upload_conn = dynamic_cast<HttpUploadConnection *>(c);
    if(upload_conn) {
        if(resend_queue_max && failed_upload_events.size()>=resend_queue_max){
            ERROR("reached max resend queue size %d. drop failed upload request",resend_queue_max);
            upload_conn->post_response_event();
            return;
        }
        failed_upload_events.emplace(new HttpUploadEvent(upload_conn->get_event()));
        return;
    }

    HttpPostConnection *post_conn = dynamic_cast<HttpPostConnection *>(c);
    if(post_conn) {
        if(resend_queue_max && failed_post_events.size()>=resend_queue_max){
            ERROR("reached max resend queue size %d. drop failed post request",resend_queue_max);
            post_conn->post_response_event();
            return;
        }
        failed_post_events.emplace(new HttpPostEvent(post_conn->get_event()));
        return;
    }
}

void HttpClient::on_resend_timer_event()
{
    while(!failed_upload_events.empty()){
        HttpUploadEvent *e = failed_upload_events.front();
        on_upload_request(*e);
        delete e;
        failed_upload_events.pop();
    }
    while(!failed_post_events.empty()){
        HttpPostEvent *e = failed_post_events.front();
        on_post_request(*e);
        delete e;
        failed_post_events.pop();
    }

    resend_timer.read();
}

void HttpClient::on_connection_delete(CurlConnection *c)
{
    invalid_ptrs.add(c);
}

void HttpClient::showStats(AmArg &ret)
{
    ret["upload_resend_queue_size"] = failed_upload_events.size();
    ret["post_resend_queue_size"] = failed_post_events.size();
    ret["resend_queue_max "] = (long int)resend_queue_max;
    ret["resend_interval"] = resend_interval;
}


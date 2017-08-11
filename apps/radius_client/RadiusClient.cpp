#include "RadiusClient.h"

#include "AmSessionContainer.h"
#include "log.h"

#define MOD_NAME "radius_client"

#include <vector>
using std::vector;

#define EPOLL_MAX_EVENTS    2048
#define TIMEOUT_CHECKING_INTERVAL 10000 //microseconds

EXPORT_PLUGIN_CLASS_FACTORY(RadiusClient, MOD_NAME);

#define SHOW_METHOD_MACRO(container,container_type,method) \
    ret.assertArray(); \
    if(args.size()) { \
        unsigned int id; \
        args.assertArrayFmt("s"); \
        if(str2i(args.get(0).asCStr(),id)) { \
            throw AmSession::Exception(500,"invalid connection id"); \
        } \
        AmLock l(connections_mutex); (void)l; \
        container_type::iterator it = container.find(id); \
        if(it!=container.end()) { \
            ret.push(AmArg()); \
            it->second->method(ret.back()); \
        } \
        return; \
    } \
    AmLock l(connections_mutex); (void)l; \
    for(container_type::iterator it = container.begin(); \
        it != container.end(); it++) \
    { \
        ret.push(AmArg()); \
        it->second->method(ret.back()); \
    } \

RadiusClient* RadiusClient::_instance=0;

RadiusClient* RadiusClient::instance()
{
    if(_instance == NULL){
        _instance = new RadiusClient(MOD_NAME);
    }
    return _instance;
}

RadiusClient::RadiusClient(const string& name)
  : AmDynInvokeFactory(name),
    AmEventFdQueue(this),
    epoll_fd(-1),
    stopped(false)
{}

RadiusClient::~RadiusClient()
{}

int RadiusClient::onLoad() {
    return 0;
}

int RadiusClient::init()
{
    if((epoll_fd = epoll_create(10)) == -1){
        ERROR("epoll_create call failed");
        return -1;
    }

    timer.set(TIMEOUT_CHECKING_INTERVAL);

    epoll_link(epoll_fd);
    stop_event.link(epoll_fd);
    timer.link(epoll_fd);

    DBG("RadiusClient initialized");
    return 0;
}

void RadiusClient::invoke(const string& method, const AmArg& args, AmArg& ret)
{
    if(method=="r"){
        getAccRules(args,ret);
    } else if(method=="addAuthConnection"){
        ret = addAuthConnection(
            args.get(0).asInt(),    //connection_id
            args.get(1).asCStr(),   //name
            args.get(2).asCStr(),   //server
            args.get(3).asInt(),    //port
            args.get(4).asCStr(),   //secret
            args.get(5).asBool(),   //reject_on_error
            args.get(6).asInt(),    //timeout_msec
            args.get(7).asInt(),    //attempts
            args.get(8)             //avps
        );
    } else if(method=="addAccConnection"){
        ret = addAccConnection(
            args.get(0).asInt(),    //connection_id
            args.get(1).asCStr(),   //name
            args.get(2).asCStr(),   //server
            args.get(3).asInt(),    //port
            args.get(4).asCStr(),   //secret
            args.get(5).asInt(),    //timeout_msec
            args.get(6).asInt(),    //attempts
            args.get(7),            //start_avps
            args.get(8),            //interim_avps
            args.get(9),            //stop_avps
            args.get(10).asBool(),  //enable_start_accounting
            args.get(11).asBool(),  //enable_interim_accounting
            args.get(12).asBool(),  //enable_stop_accounting
            args.get(13).asInt()    //interim_accounting_interval
        );
    } else if(method=="clearAuthConnections"){
        clearAuthConnections();
        ret = 0;
    } else if(method=="clearAccConnections"){
        clearAccConnections();
        ret = 0;
    } else if(method=="showAuthConnections"){
        showAuthConnections(args,ret);
    } else if(method=="showAccConnections"){
        showAccConnections(args,ret);
    } else if(method=="showAuthStat"){
        showAuthStat(args,ret);
    } else if(method=="showAccStat"){
        showAccStat(args,ret);
    } else if(method=="start"){
        start();
    } else if(method=="init"){
        ret = init();
    } else {
        throw AmDynInvoke::NotImplemented(method);
    }
}

void RadiusClient::run()
{
    int ret;
    bool running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    setThreadName("radius-client");

    AmEventDispatcher::instance()->addEventQueue(RADIUS_EVENT_QUEUE, this);

    running = true;
    do {
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if(ret == -1 && errno != EINTR){
            ERROR("epoll_wait: %s\n",strerror(errno));
        }

        if(ret < 1)
            continue;

        connections_mutex.lock();
        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            int f = e.data.fd;

            if(!(e.events & EPOLLIN)){
                continue;
            }

            if(f==timer){
                check_timeouts();
                timer.read();
            } else if(f== -queue_fd()){
                clear_pending();
                processEvents();
            } else if(f==stop_event){
                stop_event.read();
                running = false;
                break;
            } else {
                on_packet(f);
            }
        }
        connections_mutex.unlock();

    } while(running);

    epoll_unlink(epoll_fd);
    close(epoll_fd);
    AmEventDispatcher::instance()->delEventQueue(RADIUS_EVENT_QUEUE);

    stopped.set(true);

    DBG("RadiusClient stopped");
}

void RadiusClient::on_stop()
{
    stop_event.fire();
    stopped.wait_for();
}

void RadiusClient::process(AmEvent* ev)
{
    if (ev->event_id == E_SYSTEM) {
        AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(ev);
        if(sys_ev && sys_ev->sys_event == AmSystemEvent::ServerShutdown){
            stop_event.fire();
        }
        return;
    }
    RadiusRequestEvent *radius_request = dynamic_cast<RadiusRequestEvent *>(ev);
    if(radius_request){
        switch(ev->event_id){
        case RadiusRequestEvent::Auth:
            onRadiusAuthRequest(*radius_request);
            break;
        case RadiusRequestEvent::Accounting:
            onRadiusAccRequest(*radius_request);
            break;
        }
        return;
    }
    WARN("unknown event received");
}

void RadiusClient::onRadiusAuthRequest(const RadiusRequestEvent &req)
{
    DBG("process radius auth request from session %s",req.session_id.c_str());
    AuthConnections::iterator it = auth_connections.find(req.server_id);
    if(it==auth_connections.end()){
        ERROR("invalid server_id in request from %s",
              req.session_id.c_str());
        if(!AmSessionContainer::instance()->postEvent(
            req.session_id,
            new RadiusReplyEvent(RadiusReplyEvent::Error,
                                 RADIUS_INVALID_SERVER_ID,
                                 true)))
        {
            ERROR("can't post reply event to session %s",
                  req.session_id.c_str());
        }
        return;
    }
    it->second->AccessRequest(req);
}

int RadiusClient::addAuthConnection(
    unsigned int connection_id,
    string name,
    string server,
    unsigned short port,
    string secret,
    bool reject_on_error,
    unsigned int timeout_msec,
    unsigned int attempts,
    AmArg avps)
{
    struct epoll_event ev;
    AmLock l(connections_mutex); (void)l;

    DBG("add auth connection %d to %s:%d. timeout = %ims, attempts = %i, reject_on_error = %d",
        connection_id,server.c_str(),port,
        timeout_msec,attempts,reject_on_error);

    if(auth_connections.find(connection_id)!=auth_connections.end()){
        ERROR("attempt to add auth connection with duplicate connection id");
        return -1;
    }

    RadiusAuthConnection *c = new RadiusAuthConnection(
        connection_id,
        name,
        server,
        port,
        secret,
        reject_on_error,
        timeout_msec,
        attempts,
        avps);

    if(0!=c->init())
    {
        DBG("auth connection initialization error");
        delete c;
        return -1;
    }

    auth_connections[connection_id] = c;
    sock2connection[c->get_sock()] = c;

    ev.events = EPOLLIN;
    ev.data.fd = c->get_sock();
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, c->get_sock(), &ev) == -1){
        ERROR("can't add auth connection socket %d to epoll",c->get_sock());
        return -1;
    }

    return 0;
}

void RadiusClient::clearAuthConnections()
{
    AmLock l(connections_mutex); (void)l;
    for(AuthConnections::iterator it = auth_connections.begin();
        it != auth_connections.end(); it++)
    {
        const RadiusAuthConnection *c = it->second;
        int sock = c->get_sock();
        if(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, sock, NULL) == -1){
            WARN("epoll_ctl error on delete operation for socket %d: %s",
                 sock,strerror(errno));
        }
        sock2connection.erase(sock);
        delete c;
    }
    auth_connections.clear();
}

void RadiusClient::check_timeouts()
{
    for(AuthConnections::iterator it = auth_connections.begin();
        it != auth_connections.end(); it++)
    {
        it->second->check_timeouts();
    }
    for(AccConnections::iterator it = acc_connections.begin();
        it != acc_connections.end(); it++)
    {
        it->second->check_timeouts();
    }
}

void RadiusClient::on_packet(int sock)
{
    Connections::iterator it = sock2connection.find(sock);
    if(it!=sock2connection.end()){
        DBG("process incoming packets for connection %d",
            it->first);
        it->second->process();
    }
}

void RadiusClient::showAuthConnections(const AmArg &args, AmArg &ret)
{
    SHOW_METHOD_MACRO(auth_connections,AuthConnections,getInfo);
}

void RadiusClient::showAuthStat(const AmArg &args, AmArg &ret)
{
    SHOW_METHOD_MACRO(auth_connections,AuthConnections,getStat);
}

void RadiusClient::getAccRules(const AmArg &args, AmArg &ret)
{
    int connection_id = args.asInt();
    AmLock l(connections_mutex); (void)l;
    AccConnections::iterator it = acc_connections.find(connection_id);
    if(it==acc_connections.end()){
        ret.clear();
        ERROR("invalid radius acc profile id %d on rules request",
              connection_id);
        return;
    }
    it->second->get_rules(ret);
}

void RadiusClient::onRadiusAccRequest(const RadiusRequestEvent &req)
{
    DBG("process radius acc request from session %s",req.session_id.c_str());
    AccConnections::iterator it = acc_connections.find(req.server_id);
    if(it==acc_connections.end()){
        ERROR("invalid server_id in request from %s",
              req.session_id.c_str());
        return;
    }
    it->second->AccountingRequest(req);
}

int RadiusClient::addAccConnection(
    unsigned int connection_id,
    string name,
    string server,
    unsigned short port,
    string secret,
    unsigned int timeout_msec,
    unsigned int attempts,
    AmArg start_avps,
    AmArg interim_avps,
    AmArg stop_avps,
    bool enable_start_accounting,
    bool enable_interim_accounting,
    bool enable_stop_accounting,
    int interim_accounting_interval)
{
    struct epoll_event ev;
    AmLock l(connections_mutex); (void)l;

    DBG("add acc connection %d to %s:%d. timeout = %ims, attempts = %i",
        connection_id,server.c_str(),port,
        timeout_msec,attempts);

    if(acc_connections.find(connection_id)!=acc_connections.end()){
        ERROR("attempt to add acc connection with duplicate connection id");
        return -1;
    }

    RadiusAccConnection *c = new RadiusAccConnection(
        connection_id,
        name,
        server,
        port,
        secret,
        timeout_msec,
        attempts,
        start_avps,
        interim_avps,
        stop_avps,
        enable_start_accounting,
        enable_interim_accounting,
        enable_stop_accounting,
        interim_accounting_interval
    );

    if(0!=c->init())
    {
        DBG("acc connection initialization error");
        delete c;
        return -1;
    }

    acc_connections[connection_id] = c;
    sock2connection[c->get_sock()] = c;

    ev.events = EPOLLIN;
    ev.data.fd = c->get_sock();
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, c->get_sock(), &ev) == -1){
        ERROR("can't add acc connection socket %d to epoll",c->get_sock());
        return -1;
    }

    return 0;
}


void RadiusClient::clearAccConnections()
{
    AmLock l(connections_mutex); (void)l;
    for(AccConnections::iterator it = acc_connections.begin();
        it != acc_connections.end(); it++)
    {
        const RadiusAccConnection *c = it->second;
        int sock = c->get_sock();
        if(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, sock, NULL) == -1){
            WARN("epoll_ctl error on delete operation for socket %d: %s",
                 sock,strerror(errno));
        }
        sock2connection.erase(sock);
        delete c;
    }
    acc_connections.clear();
}

void RadiusClient::showAccConnections(const AmArg &args, AmArg &ret)
{
    SHOW_METHOD_MACRO(acc_connections,AccConnections,getInfo);
}

void RadiusClient::showAccStat(const AmArg &args, AmArg &ret)
{
    SHOW_METHOD_MACRO(acc_connections,AccConnections,getStat);
}

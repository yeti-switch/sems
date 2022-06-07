#include "BusClient.h"

#include "AmSessionContainer.h"
#include "AmEventDispatcher.h"
#include "AmLcConfig.h"
#include "AmPlugIn.h"
#include "AmUtils.h"
#include "log.h"
#include "jsonArg.h"
#include "ampi/SIPRegistrarClientAPI.h"
#include "cfg_opts.h"

#include <netdb.h>
#include <fnmatch.h>
#include <lzo/lzoconf.h>

#define MOD_NAME "bus_client"
#define EPOLL_MAX_EVENTS    256

using std::list;

static unsigned long TIME_RESOLUTION = 1000000UL;
//static unsigned long TICKS_PER_SEC = (1000000UL / TIME_RESOLUTION);
static unsigned long QUERY_TIMER_RESOLUTION = 1000000UL;

BusClient* BusClient::_instance=0;

EXPORT_PLUGIN_CLASS_FACTORY(BusClient);
EXPORT_PLUGIN_CONF_FACTORY(BusClient);

BusClient* BusClient::instance()
{
    if (_instance == NULL)
        _instance = new BusClient(MOD_NAME);
    return _instance;
}

BusClient::BusClient(const string& name)
    : AmDynInvokeFactory(name),
      AmConfigFactory(name),
      AmEventFdQueue(this),
      timer_val(0),
      stopped(false),
      epoll_fd(-1),
      tostop(false),
      active_connections(0)
{
    _instance = this;
}

BusClient::BusClient()
    : BusClient(MOD_NAME)
{}

BusClient::~BusClient()
{
    ::close(epoll_fd);

    for (int slot=0; slot<active_connections; ++slot)
        delete conn[slot];
}

bool BusClient::init_connections()
{
    for (map<string, sockaddr_storage>::const_iterator it=bus_nodes.begin();
         it != bus_nodes.end();
         ++it)
    {
        if (active_connections < BUS_CONNECTION_MAX) {
            bus_nodes_index.insert(std::make_pair(it->first, active_connections));
            const sockaddr_storage &saddr = it->second;

            conn[active_connections] = new BusConnection(
                this, saddr,
                active_connections,
                config.reconnect_interval,
                AmConfig.node_id,
                config.so_rcvbuf,
                config.so_sndbuf);

            if (!conn[active_connections]) {
                ERROR("BusConnection creation failed");
                return false;
            }

            ++active_connections;
        } else {
            ERROR("Too many BusConnections, %d MAX", BUS_CONNECTION_MAX);
            return false;
        }
    }

    return true;
}

bool BusClient::init_routing()
{
    for(auto& method : route_methods) {
        for(auto& conn_group : method.second) {
            for(auto& c: conn_group.second) {
                auto bus_it = bus_nodes_index.find(c.second.name_conn);
                if(bus_it == bus_nodes_index.end()) {
                    ERROR("unknown connection '%s' as route for method '%s'",
                          c.second.name_conn.c_str(), method.first.name.c_str());
                    return false;
                }
                c.second.conn = conn[bus_it->second];
            }
        }
    }
    return true;
}

int BusClient::init()
{
    lzo_init();
    if((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    if (!init_connections() || 
        !init_routing())
        return -1;

    timer.set(TIME_RESOLUTION);
    timer.link(epoll_fd);
    query_timer.set(QUERY_TIMER_RESOLUTION);
    query_timer.link(epoll_fd);
    epoll_link(epoll_fd);
    stop_event.link(epoll_fd);

    //init dynamic queues
    for(auto const &dyn_q: config.dynamic_queues) {
        BusDynamicQueue *q = new BusDynamicQueue(this,dyn_q.name, dyn_q.application);
        q->epoll_link(epoll_fd);
        dynamic_queues.emplace(q->queue_fd(),std::unique_ptr<BusDynamicQueue>(q));
    }

    INFO("BusClient initialized");
    return 0;
}

int BusClient::onLoad()
{
    init_rpc();

    if (init()) {
        ERROR("initialization error");
        return -1;
    }

    start();
    return 0;
}

void BusClient::on_stop()
{
    stop_event.fire();
    stopped.wait_for();
}

void BusClient::on_timer()
{
    for (int slot=0; slot<active_connections; ++slot)
        conn[slot]->on_timer(timer_val);
}

void BusClient::on_timer_query()
{
    for(auto query = query_map.begin(); query != query_map.end();) {
        if(query_timer_val - query->second.query_time > query->second.timeout) {
            AmArg data;
            map<string, string> params;
            params["error"] = "bus timeout";
            data["error"] = "bus timeout";
            data["app_method"] = query->second.msg->application_method;
            BusReplyEvent* ev = new BusReplyEvent(BusReplyEvent::Error, params, data);
            if(!AmSessionContainer::instance()->postEvent(query->second.msg->local_tag, ev)) {
                DBG("couldn't post to event queue: '%s'",query->second.msg->local_tag.c_str());
            }
            delete query->second.msg;
            query = query_map.erase(query);
        } else {
            query++;
        }
    }
}

void BusClient::on_query_response(uint32_t seq)
{
    auto query = query_map.find(seq);
    if(query != query_map.end())
        delete query->second.msg;
    query_map.erase(seq);
}

BusClient::route_methods_container::const_iterator BusClient::matchRouteMethod(const string &app_method)
{
    return std::find_if(
        route_methods.begin(), route_methods.end(),
        [&app_method](const route_methods_container::value_type &v) -> bool {
            return 0==fnmatch(v.first.name.c_str(), app_method.c_str(),0);
        });
}

BusClient::send_conn_result_t BusClient::sendMessagetoConnection(BusConnection* c, BusMsg* msg)
{
    if(!c) {
        WARN("null connection");
        return CONN_WARNING;
    }
    if(c->get_state() != BusConnection::Connected) {
        WARN("got connection in not Connected state");
        return CONN_WARNING;
    }

    uint32_t seq;
    if(c->sendMsg(msg, seq)) {
        if(msg->is_query) {
            bus_query_param_t query;
            query.query_time = query_timer_val;
            query.timeout = msg->timeout ? msg->timeout : config.query_timeout;
            query.msg = new BusMsg(*msg);
            query_map.insert(std::make_pair(seq, query));
        }
        return CONN_OK;
    } else {
        WARN("failed to send message");
    }

    return CONN_ERROR;
}

void BusClient::sendMsg(BusMsg *msg)
{
    unsigned int w_sum;
    const route_conn_params_t *route_data;

    const auto method_it = matchRouteMethod(msg->application_method);
    if(method_it == route_methods.end()) {
        AmArg data;
        map<string, string> params;

        params["error"] = "no matched route";
        data["error"] = "no matched route";
        data["app_method"] = msg->application_method;

        BusReplyEvent* ev = new BusReplyEvent(BusReplyEvent::Error, params, data);
        if(!AmSessionContainer::instance()->postEvent(msg->local_tag, ev)) {
            DBG("couldn't post to event queue: '%s'",msg->local_tag.c_str());
        }

        return;
    }

    auto &method = method_it->second;
    bool broadcast = method_it->first.broadcast;

    for(auto const &failover_group: method) {
        const auto &balancing_group = failover_group.second;

        DBG("try group with priority %d, size: %zd for method %s from session %s",
            failover_group.first,
            balancing_group.size(),
            method_it->first.name.c_str(),
            msg->local_tag.c_str());
        if(!broadcast) {
            if(1==balancing_group.size()) {
                //skip balancing for group with 1 connection only
                route_data = &balancing_group.begin()->second;
            } else{
                //skip balancing for method with broadcast option
                list<pair<unsigned int, route_methods_balancing_group_t::const_iterator> > weights_list;

                //prepare list with running sum
                w_sum = 0;
                for(auto c_it = balancing_group.cbegin();
                    c_it != balancing_group.cend();
                    c_it++)
                {
                    if(!c_it->second.conn || c_it->second.conn->get_state() != BusConnection::Connected)
                        continue;
                    w_sum += c_it->second.weight;
                    weights_list.emplace_back(w_sum,c_it);
                }

                if(weights_list.empty()) {
                    DBG("no active connections in group with priority %d for route %s. skip it",
                        failover_group.first,method_it->first.name.c_str());
                    continue;
                }

                unsigned int r = random() % (w_sum+1);

                route_data = nullptr;
                for(const auto& w : weights_list) {
                    if(w.first >= r) {
                        route_data = &w.second->second;
                        break;
                    }
                }
                if(!route_data) {
                    ERROR("BUG: SRV balancing implementation error r = %u. use first active of the candidates",
                        r);
                    route_data = &weights_list.begin()->second->second;
                }
            }

            send_conn_result_t res = sendMessagetoConnection(route_data->conn, msg);
            if(res == CONN_OK) return;
            else if(res == CONN_WARNING) {
                WARN("error in connection %s after balancing", route_data->name_conn.c_str());
                continue;
            }
        } else {
            for(auto c_it = balancing_group.cbegin();
                    c_it != balancing_group.cend();
                    c_it++) {
                send_conn_result_t res = sendMessagetoConnection(c_it->second.conn, msg);
                if(res != CONN_OK) {
                    WARN("error for connection %s in broadcast method group: %s",
                         c_it->second.name_conn.data(),
                         method_it->first.name.data());
                    continue;
                }
            }
        }

    }

    AmArg data;
    map<string, string> params;

    params["error"] = "failed to send msg using matched route";
    data["error"] = "failed to send msg using matched route";
    data["app_method"] = msg->application_method;
    data["matched_route"] = method_it->first.name;

    BusReplyEvent* ev = new BusReplyEvent(BusReplyEvent::Error, params, data);
    if(!AmSessionContainer::instance()->postEvent(msg->local_tag, ev)) {
        DBG("couldn't post to event queue: '%s'",msg->local_tag.c_str());
    }
}

void BusClient::process(AmEvent* ev)
{
    if (ev->event_id == E_SYSTEM) {
        if(AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(ev)) {
            DBG("received system event");
            if (sys_ev->sys_event == AmSystemEvent::ServerShutdown)
                stop_event.fire();
        }
        return;
    }

    if(BusMsg *msg = dynamic_cast<BusMsg *>(ev)) {
        sendMsg(msg);
        return;
    }

    WARN("got unknown event");
}

void BusClient::run()
{
    setThreadName("event-bus");

    AmEventDispatcher::instance()->addEventQueue(BUS_EVENT_QUEUE, this);

    for(auto &dyn_queue_it: dynamic_queues) {
        BusDynamicQueue &q = *dyn_queue_it.second.get();
        DBG("register dynamic queue '%s' with fd %d",
            q.getQueueName().c_str(),dyn_queue_it.first);
        AmEventDispatcher::instance()->addEventQueue(q.getQueueName(), &q);
    }

    do {
        struct epoll_event events[BUS_DISPATCHER_MAX_EPOLL_EVENT];

        int ret = epoll_wait(epoll_fd, events, BUS_DISPATCHER_MAX_EPOLL_EVENT, -1);


        if (ret == -1 && errno != EINTR)
            ERROR("%s: epoll_wait(): %m", __func__);

        if (ret < 1) {
            usleep(100000);
            continue;
        }

        //DBG("got %d events",ret);
        for (int n=0; n < ret; ++n ) {
            uint32_t ev         = events[n].events;
            int      ev_info    = events[n].data.fd;

            /*DBG("ev: %d, ev_info: %d",
                ev,ev_info);*/

            if(ev_info >= 0) {
                conn[ev_info]->handler(ev);
                continue;
            }

            if(timer==ev_info) {
                timer_val += timer.read();
                on_timer();
            } else if(query_timer==ev_info) {
                query_timer_val += query_timer.read();
                on_timer_query();
            } else if(-queue_fd()==ev_info) {
                clear_pending();
                processEvents();
            } else if(stop_event==ev_info) {
                stop_event.read();
                tostop = true;
            } else {
                DynamicQueuesMap::iterator it = dynamic_queues.find(-ev_info);
                if(it==dynamic_queues.end()) {
                    DBG("event for unknown dynamic queue. fd: %d",ev_info);
                    continue;
                }
                it->second->clear_pending();
                it->second->processEvents();
            }
        }

    } while (!tostop);

    AmEventDispatcher::instance()->delEventQueue(BUS_EVENT_QUEUE);
    epoll_unlink(epoll_fd);

    for(auto &dyn_queue_it: dynamic_queues) {
        BusDynamicQueue &q = *dyn_queue_it.second.get();
        AmEventDispatcher::instance()->delEventQueue(q.getQueueName());
        q.epoll_unlink(epoll_fd);
    }

    close(epoll_fd);

    DBG("BusClient stopped");

    stopped.set(true);
}

bool BusClient::link(int fd, int op, struct epoll_event &ev)
{
    int ret = epoll_ctl(epoll_fd, op, fd, &ev);

    if (ret != -1)
        return true;

    ERROR("epoll_ctl(): %m");
    return false;
}

int BusClient::configure(const string& config_)
{
    cfg_t* cfg = cfg_init(bus_client_opts, CFGF_NONE);
    if(!cfg) return -1;
    switch(cfg_parse_buf(cfg, config_.c_str())) {
    case CFG_SUCCESS:
        break;
    case CFG_PARSE_ERROR:
        ERROR("configuration of module %s parse error", MOD_NAME);
        cfg_free(cfg);
        return -1;
    default:
        ERROR("unexpected error on configuration of module %s processing", MOD_NAME);
        cfg_free(cfg);
        return -1;
    }

    AmLcConfig::instance().getMandatoryParameter(cfg, PARAM_RECONN_INT_NAME, config.reconnect_interval);
    AmLcConfig::instance().getMandatoryParameter(cfg, PARAM_QUERY_TIMEOUT_NAME, config.query_timeout);
    AmLcConfig::instance().getMandatoryParameter(cfg, PARAM_SHUTDOWN_CODE_NAME, config.shutdown_code);
    AmLcConfig::instance().getMandatoryParameter(cfg, PARAM_SO_RCVBUF_NAME, config.so_rcvbuf);
    AmLcConfig::instance().getMandatoryParameter(cfg, PARAM_SO_SNDBUF_NAME, config.so_sndbuf);

    for(unsigned int i = 0; i < cfg_size(cfg, SECTION_BUS_NODE_NAME); i++) {
        sockaddr_storage addr;
        string address;
        int port;

        cfg_t* node = cfg_getnsec(cfg, SECTION_BUS_NODE_NAME, i);
        AmLcConfig::instance().getMandatoryParameter(node, PARAM_ADDRESS_NAME, address);
        AmLcConfig::instance().getMandatoryParameter(node, PARAM_PORT_NAME, port);

        if (!am_inet_pton(address.c_str(), &addr)) {
            // try to resolve hostname, only AF_INET now
            struct hostent      *he;

            if ((he = gethostbyname(address.c_str())) == NULL) {
                ERROR("Bad bus host param: gethostbyname(): %m");
                cfg_free(cfg);
                return -1;
            }

            addr.ss_family = AF_INET;

            memcpy( &(reinterpret_cast<struct sockaddr_in*>(&addr))->sin_addr,
                    he->h_addr_list[0],
                    he->h_length);
        }

        am_set_port(&addr, port);
        bus_nodes.insert(std::make_pair(node->title, addr));
    }

    if(bus_nodes.empty()) {
        ERROR("absent connections section\n");
        cfg_free(cfg);
        return -1;
    }
    
    cfg_t* routing;
    if(cfg_size(cfg, SECTION_ROUTING_NAME)) {
        routing = cfg_getsec(cfg, SECTION_ROUTING_NAME);
    } else {
        ERROR("absent routing section\n");
        cfg_free(cfg);
        return -1;
    }
    
    for(unsigned int i = 0; i < cfg_size(routing, SECTION_METHOD_NAME); i++) {
        route_method_t route_method;
        cfg_t* method = cfg_getnsec(routing, SECTION_METHOD_NAME, i);
        map<int, bool> zero_weigth;
        bool broadcast = cfg_getbool(method, PARAM_BROADCAST_NAME);
        for(unsigned int i = 0; i < cfg_size(method, SECTION_BUS_NODE_NAME); i++) {
            cfg_t* bus_node = cfg_getnsec(method, SECTION_BUS_NODE_NAME, i);
            route_conn_params_t param;
            param.name_conn = bus_node->title;
            param.priority = cfg_getint(bus_node, PARAM_PRIORITY_NAME);
            param.weight = cfg_getint(bus_node, PARAM_WEIGHT_NAME);
            zero_weigth[param.priority] = true;
            if(param.weight) zero_weigth[param.priority] = false;
            route_method[param.priority].emplace(param.weight,param);
        }
        for(auto& route : route_method) {
            BusClient::route_methods_balancing_group_t balance;
            for(auto iter = route.second.begin(); iter != route.second.end(); iter++) {
                if(zero_weigth[route.first]) {
                    iter->second.weight = 100/route.second.size();
                    balance.emplace(iter->second.weight, iter->second);
                } else if(iter->first){
                    balance.emplace(iter->first, iter->second);
                }
            }
            route.second = balance;
        }
        if(route_method.empty()) {
            ERROR("absent connections in method %s section\n", method->title);
            cfg_free(cfg);
            return -1;
        }
        route_methods.emplace_back(route_method_param_t{.name = method->title, .broadcast = broadcast}, route_method);
    }

    for(unsigned int i = 0; i < cfg_size(cfg, SECTION_DYN_QUEUE_NAME); i++) {
        string app;
        cfg_t* queue = cfg_getnsec(cfg, SECTION_DYN_QUEUE_NAME, i);
        AmLcConfig::instance().getMandatoryParameter(queue, PARAM_APP_NAME, app);
        config_t::dynamic_queue_config_t queue_config = {
            .name = queue->title,
            .application = app
        };
        config.dynamic_queues.emplace_back(queue_config);
    }
    cfg_free(cfg);
    return 0;
}

int BusClient::reconfigure(const string&)
{
    return 0;
}

void BusClient::postEvent(const AmArg& args, AmArg& ret)
{
    try {
        args.assertArrayFmt("ssss");
    } catch(...) {
        throw AmSession::Exception(500,"usage: postEvent is_query local_tag application body");
    }

    bool is_query;
    str2bool(args[0].asCStr(),is_query);

    if(!AmSessionContainer::instance()->postEvent(
        BUS_EVENT_QUEUE,
        new BusMsg( is_query,
                    args[2].asCStr(),   //session_id
                    args[3].asCStr(),   //application_method
                    args[4].asCStr()))) //body
    {
        throw AmSession::Exception(500,"can't post bus event. possible missed bus_client module");
    }
    ret = 200;
}

void BusClient::showConnections(const AmArg&, AmArg& ret)
{
    ret.assertArray();
    for(int i = 0; i < active_connections; i++) {
        ret.push(AmArg());
        AmArg &node = ret.back();
        conn[i]->getInfo(node);
    }
}

void BusClient::fillRouteInfo(AmArg &route, const route_methods_container::value_type &route_data)
{
    route["pattern"] = route_data.first.name;
    route["broadcast"] = route_data.first.broadcast;
    AmArg &groups = route["connections"];
    groups.assertStruct();
    for(auto& conn_group : route_data.second) {
        AmArg &group = groups[int2str(conn_group.first)];
        for(auto& c: conn_group.second) {
            group.push(AmArg());
            AmArg &connection = group.back();
            const route_conn_params_t &cparam = c.second;
            connection["weight"] = c.first;
            connection["name"] = cparam.name_conn;
            if(cparam.conn) {
                connection["state"] = BusConnection::state_to_str(cparam.conn->get_state());
            }
        }
    }
}

void BusClient::showRoutes(const AmArg&, AmArg& ret)
{
    ret.assertArray();
    for(auto& method : route_methods) {
        ret.push(AmArg());
        AmArg &route = ret.back();
        fillRouteInfo(route, method);
    }
}

void BusClient::requestRoutesTest(const AmArg& args, AmArg& ret)
{
    if(!args.size() || !isArgCStr(args[0])) {
        throw AmSession::Exception(500, "method string required");
    }
    const auto method_it = matchRouteMethod(args[0].asCStr());
    if(method_it != route_methods.end()) {
        ret["result"] = "matched";
        ret["route_pattern"] = method_it->first.name;
        ret["route_index"] = std::distance(route_methods.cbegin(), method_it);
        fillRouteInfo(ret["route"], *method_it);
    } else {
        ret["result"] = "NOT matched";
    }
}

void BusClient::init_rpc_tree()
{
    reg_method(root,"postEvent","",&BusClient::postEvent);

    AmArg &show = reg_leaf(root,"show","");
    reg_method(show,"connections","",&BusClient::showConnections);
    reg_method(show,"routes","",&BusClient::showRoutes);

    AmArg &request = reg_leaf(root,"request","");
    AmArg &request_routes = reg_leaf(request,"routes","");
    reg_method(request_routes,"test","",&BusClient::requestRoutesTest);
}

void BusDynamicQueue::process(AmEvent* ev)
{
    if(SIPRegistrationEvent *sip_reg = dynamic_cast<SIPRegistrationEvent *>(ev))
    {
        SIPRegistrationEvent &e = *sip_reg;
        DBG("[%s] got SIPRegistrationEvent event_id:%d, handle: %s, id: %s, code/reason: %d/%s",
            queue_name.c_str(),
            e.event_id,
            e.handle.c_str(),
            e.id.c_str(),
            e.code,e.reason.c_str());

        AmArg body;
        body["handle"] = e.handle;
        body["event_id"] = e.event_id;
        body["id"] = e.id;
        body["code"] = (unsigned long)e.code;
        body["reason"] = e.reason;

        BusMsg msg(false, string(),application,arg2json(body));
        bus->sendMsg(&msg);
        return;
    }

    if(dynamic_cast<AmSystemEvent*>(ev)) {
        //ignore system events. like ServerShutdown
        return;
    }

    WARN("[%s] got unknown event",queue_name.c_str());
}


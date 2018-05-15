#include "SctpBus.h"

#include "cfg_opts.h"

#include "AmSessionContainer.h"
#include "AmPlugIn.h"
#include "log.h"
#include "sip/ip_util.h"

#include "SctpClientConnection.h"
#include "SctpServerConnection.h"

#define MOD_NAME "sctp_bus"

#include <vector>
using std::vector;

#define EPOLL_MAX_EVENTS    2048
#define TIMEOUT_CHECKING_INTERVAL 3000000 //microseconds

struct ReloadEvent
  : public AmEvent
{
  ReloadEvent()
    : AmEvent(0)
  {}
};

//EXPORT_PLUGIN_CLASS_FACTORY(SctpBus, MOD_NAME);

EXPORT_MODULE_FACTORY(SctpBus);
DEFINE_MODULE_INSTANCE(SctpBus, MOD_NAME);

//SctpBus* SctpBus::_instance=0;

/*SctpBus* SctpBus::instance()
{
    DBG("> instance = %p",_instance);
    if(_instance == NULL){
        _instance = new SctpBus(MOD_NAME);
    }
    DBG("instance = %p",_instance);
    return _instance;
}*/

SctpBus::SctpBus(const string& name)
  : AmDynInvokeFactory(name),
    AmEventFdQueue(this),
    epoll_fd(-1),
    stopped(false)
{}

SctpBus::~SctpBus()
{
    if(-1!=epoll_fd)
        close(epoll_fd);

    for(auto const &c: connections_by_id) {
        delete c.second;
    }
}

int SctpBus::configure()
{
    cfg_reader reader;
    sockaddr_storage a;

    if(!reader.read(AmConfig::ModConfigPath + string(MOD_NAME ".conf"),sctp_bus_opts)) {
        return -1;
    }

    //apply 'listen' section settings
    cfg_t *listen_cfg = cfg_getsec(reader.cfg,section_name_listen);
    if(!listen_cfg) {
        ERROR("configuration error. missed section: listen");
        return -1;
    }
    if(!am_inet_pton(cfg_getstr(listen_cfg,opt_name_address),&a)) {
        ERROR("configuration error. invalid address '%s' in listen section",
              cfg_getstr(listen_cfg,opt_name_address));
        return -1;
    }
    am_set_port(&a,cfg_getint(listen_cfg,opt_name_port));
    if(0!=server_connection.init(epoll_fd,a)) {
        ERROR("failed to init sctp server connection");
        return -1;
    }

    //apply 'neighbours' section settings
    cfg_t *neighbours_cfg = cfg_getsec(reader.cfg,section_name_neighbours);
    if(neighbours_cfg) {
        cfg_t *node_cfg;
        int port, node_id, default_port, reconnect_interval;
        char *address, *default_address;

        default_port = cfg_getint(neighbours_cfg,opt_name_default_port);
        reconnect_interval = cfg_getint(neighbours_cfg,opt_name_reconnect_interval);
        default_address = cfg_getstr(neighbours_cfg,opt_name_default_address);

        //iterate nodes
        for(unsigned int j = 0; j < cfg_size(neighbours_cfg, section_name_node); j++) {
            node_cfg = cfg_getnsec(neighbours_cfg,section_name_node,j);
            if(!str2int(cfg_title(node_cfg),node_id)) {
                ERROR("invalid neighbour node id: %s",cfg_title(node_cfg));
                return -1;
            }
            address = cfg_getstr(node_cfg,opt_name_address);
            if(!address) {
                if(!default_address) {
                    ERROR("configuration error. missed address for node %d and no default address specified",
                          node_id);
                    return -1;
                }
                address = default_address;
            }
            if(!am_inet_pton(address,&a)) {
                ERROR("configuration error. invalid address '%s' for neighbour node %d",
                      address,node_id);
                return -1;
            }
            port = cfg_getint(node_cfg,opt_name_port);
            am_set_port(&a,0==port ? default_port : port);

            if(0!=addClientConnection(node_id,a,reconnect_interval)) {
                ERROR("neigbour connection %d initialization error",node_id);
                return -1;
            }
        }
    } //if(neighbours_cfg)

    DBG("SctpBus configured");
    return 0;
}

int SctpBus::onLoad() {

    AmPlugIn::registerDIInterface(getName(),this);

    if((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create failed");
        return -1;
    }

    timer.set(TIMEOUT_CHECKING_INTERVAL);

    epoll_link(epoll_fd);
    stop_event.link(epoll_fd);
    timer.link(epoll_fd);

    if(-1==configure()) {
        return -1;
    }

    init_rpc();

    AmEventDispatcher::instance()->addEventQueue(SCTP_BUS_EVENT_QUEUE, this);

    DBG("SctpBus initialized");

    start();

    return 0;
}

void SctpBus::init_rpc_tree()
{
    AmArg &show = reg_leaf(root,"show");
        AmArg &show_server = reg_leaf(show,"server");
            reg_method(show_server,"associations","",&SctpBus::showServerAssocations);
        AmArg &show_client = reg_leaf(show,"client");
            reg_method(show_client,"connections","",&SctpBus::showClientConnections);
    AmArg &request = reg_leaf(root,"request");
        reg_method(request,"reload","",&SctpBus::reload);
}

void SctpBus::run()
{
    int ret,f;
    bool running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    setThreadName("sctp-bus");

    //AmEventDispatcher::instance()->addEventQueue(SCTP_BUS_EVENT_QUEUE, this);

    running = true;
    do {
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if(ret < 1) {
            if(errno != EINTR){
                ERROR("epoll_wait: %m");
                break;
            }
            continue;
        }

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            f = e.data.fd;
            if(f==timer){
                on_timer();
                timer.read();
            } else if(f== -queue_fd()){
                clear_pending();
                processEvents();
            } else if(f==(int)server_connection) {
                server_connection.process(e.events);
            } else if(f==stop_event){
                stop_event.read();
                running = false;
                break;
            } else {
                process_client_connection(f,e.events);
            }
        }
    } while(running);

    epoll_unlink(epoll_fd);
    close(epoll_fd);
    AmEventDispatcher::instance()->delEventQueue(SCTP_BUS_EVENT_QUEUE);

    stopped.set(true);

    DBG("SctpBus stopped");
}

void SctpBus::on_stop()
{
    stop_event.fire();
    stopped.wait_for();
}

void SctpBus::process(AmEvent* ev)
{
    if (ev->event_id == E_SYSTEM) {
        AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(ev);
        if(sys_ev && sys_ev->sys_event == AmSystemEvent::ServerShutdown){
            stop_event.fire();
        }
        return;
    }

    if(SctpBusSendEvent *e = dynamic_cast<SctpBusSendEvent *>(ev)) {
        onSendEvent(*e);
        return;
    }

    if(SctpBusRawRequest *e = dynamic_cast<SctpBusRawRequest *>(ev)) {
        onSendRawRequest(*e);
        return;
    }

    if(SctpBusRawReply *e = dynamic_cast<SctpBusRawReply *>(ev)) {
        onSendRawReply(*e);
        return;
    }

    if(SctpBusAddConnection *e = dynamic_cast<SctpBusAddConnection *>(ev)) {
        onConnectionAdd(*e);
        return;
    }
    if(SctpBusRemoveConnection *e = dynamic_cast<SctpBusRemoveConnection *>(ev)) {
        onConnectionRemove(*e);
        return;
    }

    if(dynamic_cast<ReloadEvent *>(ev)) {
        onReloadEvent();
        return;
    }
    WARN("unknown event received");
}

void SctpBus::onSendEvent(const SctpBusSendEvent &e)
{
    int peer_id;

    DBG("process sctp send event %s -> %s ",
        e.src_session_id.c_str(),
        e.dst_session_id.c_str());

    size_t hyphen_pos = e.dst_session_id.find_first_of('-');
    if(hyphen_pos!=string::npos) {
        if(!str2int(e.dst_session_id.substr(0,hyphen_pos),peer_id)) {
            peer_id = 0;
        } else {
            DBG("got peer_id %d from dst session_id: %s",
                peer_id,
                e.dst_session_id.c_str());
        }
    } else {
        peer_id = 0;
    }

    if(peer_id==AmConfig::node_id) {
        WARN("destination peer_id is equal with our node_id");
    }

    if(0!=peer_id) {
        Connections::iterator it = connections_by_id.find(peer_id);
        if(it==connections_by_id.end()) {
            ERROR("unknown peer_id %d in sctp send event",
                  peer_id);
            return;
        }
        it->second->send(e);
    } else {
        DBG("peer is not detected from destination session_id %s. send to all peers",
            e.dst_session_id.c_str());
        for(auto const &c : connections_by_id)
            c.second->send(e);
    }
}

void SctpBus::onSendRawRequest(const SctpBusRawRequest &e)
{
    DBG("process sctp send raw event request %s -> %d:%s ",
        e.src_session_id.c_str(),
        e.dst_id,
        e.dst_session_id.c_str());
    Connections::iterator it = connections_by_id.find(e.dst_id);
    if(it==connections_by_id.end()) {
        DBG("connection with id %d does not exists",e.dst_id);
        return;
    }
    it->second->send(e);
}

void SctpBus::onSendRawReply(const SctpBusRawReply &e)
{
    DBG("process sctp send raw event reply %s -> %d:%s ",
        e.req.dst_session_id.c_str(),
        e.req.src_id,
        e.req.src_session_id.c_str());
    Connections::iterator it = connections_by_id.find(e.req.src_id);
    if(it==connections_by_id.end()) {
        DBG("connection with id %d does not exists",e.req.src_id);
        return;
    }
    it->second->send(e);
}

void SctpBus::onConnectionAdd(const SctpBusAddConnection &e)
{
    if(0!=addClientConnection(
        e.connection_id,
        e.remote_address,
        e.reconnect_interval,
        e.event_sink))
    {
        ERROR("failed to add external client connection with id: %d",e.connection_id);
    }
}

void SctpBus::onConnectionRemove(const SctpBusRemoveConnection &e)
{
    auto it = connections_by_id.find(e.connection_id);
    if(it==connections_by_id.end()) {
        ERROR("request to remove not existent external client connection with id: %d",
            e.connection_id);
        return;
    }

    SctpConnection *c = it->second;
    int sock = c->get_sock();
    connections_by_sock.erase(sock);
    connections_by_id.erase(e.connection_id);

    if(!c->get_event_sink().empty()) {
        AmSessionContainer::instance()->postEvent(
            c->get_event_sink(),
            new SctpBusConnectionStatus(
                e.connection_id,
                SctpBusConnectionStatus::Removed));
    }

    delete c;
}

void SctpBus::onReloadEvent()
{
    INFO("cleanup sctp_bus configuration");
    server_connection.close();
    for(auto const &c: connections_by_id) {
        delete c.second;
    }
    connections_by_id.clear();
    connections_by_sock.clear();

    INFO("load sctp_bus configuration");
    if(-1==configure()) {
        ERROR("SctpBus configuration error. please fix config and do reload again");
    } else {
        INFO("SctpBus configuration successfully reloaded");
    }
}

int SctpBus::addClientConnection(
    unsigned int id,
    const sockaddr_storage &a,
    int reconnect_interval,
    const string &event_sink)
{
    //AmLock l(connections_mutex); (void)l;

    if(connections_by_id.find(id)!=connections_by_id.end()) {
        ERROR("attempt to add connection with duplicate connection id %d",id);
        return -1;
    }

    auto c = new SctpClientConnection();
    if(0!=c->init(epoll_fd,a,reconnect_interval,event_sink))
    {
        DBG("connection %u initialization error",id);
        delete c;
        return -1;
    }
    c->set_id(id);

    int conn_sock = c->get_sock();

    connections_by_id[id] = c;
    connections_by_sock[conn_sock] = c;

    return 0;
}

void SctpBus::on_timer()
{
    int ret;

    time_t now = time(nullptr);

    server_connection.on_timer(now);
    for(auto const &c : connections_by_id) {
        ret = c.second->on_timer(now);
        if(ret > 0) {
            DBG("add fd %d to the client connections sockets map", ret);
            if(connections_by_sock.find(ret)!=connections_by_sock.end()) {
                WARN("client connections map already contains key %d. overwrite it",ret);
            }
            connections_by_sock[ret] = c.second;
        }
    }
}

void SctpBus::process_client_connection(int sock, uint32_t events)
{
    int ret;
    Connections::iterator it = connections_by_sock.find(sock);
    if(it!=connections_by_sock.end()){
        /*DBG("process events %d for connection with socket %d",
            events,it->first);*/
        ret = it->second->process(events);
        if(ret > 0) {
            DBG("remove fd %d from the client connections sockets map", ret);
            connections_by_sock.erase(it);
        }
        return;
    }
    DBG("socket %d got events (%d) for unknown client connection. close socket",sock,events);
    close(sock);
}

void SctpBus::showServerAssocations(const AmArg &args, AmArg &ret)
{
    ret.assertArray();
    server_connection.getInfo(ret);
}

void SctpBus::showClientConnections(const AmArg &args, AmArg &ret)
{
    ret.assertArray();
    //FIXME: is it safe without mutex ?
    for(auto const &c : connections_by_id) {
        ret.push(AmArg());
        AmArg &info = ret.back();
        info["id"] = (unsigned long)c.first;
        c.second->getInfo(info);
    }
}

void SctpBus::reload(const AmArg &args, AmArg &ret)
{
    AmSessionContainer::instance()->postEvent(SCTP_BUS_EVENT_QUEUE,new ReloadEvent());
}

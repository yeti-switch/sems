#include "RtspClient.h"
#include "AmSessionContainer.h"
#include "AmEventDispatcher.h"
#include "log.h"

#include <netdb.h>
#include <sys/epoll.h>
#include <cctype>
#include <algorithm>
#include <fstream>


#define MOD_NAME "rtsp_client"

#define EPOLL_MAX_EVENTS    256

RtspClient* RtspClient::_instance=0;


RtspClient* RtspClient::instance()
{
    if(_instance == NULL)
        _instance = new RtspClient(MOD_NAME);

    return _instance;
}

void RtspClient::dispose()
{
    if(_instance != NULL) {
        if(!_instance->is_stopped()) {
            _instance->stop();
            while (!_instance->is_stopped())
                usleep(10000);
        }
        delete _instance;
        _instance = NULL;
    }
}


RtspClient::RtspClient()
    : tostop(false), epoll_fd(-1), id_counter(0)
{
    _instance = this;
}


RtspClient::RtspClient(const string& name)
      : tostop(false), epoll_fd(-1), id_counter(0)
{
    _instance = this;
}


RtspClient::~RtspClient()
{
    ::close(epoll_fd);
}


bool RtspClient::srv_resolv(string host, int port, sockaddr_storage &_sa)
{
    dns_handle  _dh;

    if(config.use_dns_srv) {
        static string   rtsp_srv_prefix = string("_rtsp._tcp.");
        host = rtsp_srv_prefix + host;
    }

    dns_priority priority = IPv4_only;
    
    sockaddr_storage l_saddr;
    am_inet_pton(localMediaIP().c_str(), &l_saddr);
    if(l_saddr.ss_family == AF_INET) {
        priority = IPv4_only;
    } else {
        priority = IPv6_only;
    }
    
    if (resolver::instance()->resolve_name(host.c_str(), &_dh, &_sa, priority,
        config.use_dns_srv ? dns_r_srv : dns_r_ip) < 0) {
        ERROR("can't resolve destination: '%s'\n", host.c_str());
        return false;
    }

    if (!config.use_dns_srv)
        am_set_port(&_sa, port ? port : RTSP_DEFAULT_PORT);

    return true;
}


void RtspClient::parse_host_str(const string& host_port)
{
    int                 port = RTSP_DEFAULT_PORT;
    string              host, port_str;
    vector<string>      p = explode(host_port, ":");

    if (p.size() == 1)
        host = trim(p[0], " ");
    else if (p.size() == 2) {
        host = trim(p[0], " ");
        port_str = trim(p[1], " ");
    } else {
        ERROR("Bad host param: %s", host_port.c_str());
        return ;
    }

    if (port_str.length())
        port = atoi(port_str.c_str());

    sockaddr_storage saddr;

    if (srv_resolv(host, port, saddr))
        media_nodes.push_back(saddr);
}


size_t RtspClient::load_media_servers(const string& servers)
{
    for (auto &host : explode(servers, ";,"))
        parse_host_str(host);

    return media_nodes.size();
}


void RtspClient::init_connections()
{
    int active_connections = 0;

    for (auto& saddr : media_nodes)
        rtsp_session.emplace_back(this, saddr, active_connections++);
}


int RtspClient::configure()
{
    AmConfigReader cfg;

    if (cfg.loadFile(AmConfig::ModConfigPath + string(MOD_NAME ".conf")))
        return -1;

    config.max_queue_length     = cfg.getParameterInt("max_queue_length", 0);
    config.reconnect_interval   = cfg.getParameterInt("reconnect_interval", 10);
    config.shutdown_code        = cfg.getParameterInt("shutdown_code", 503);
    config.media_servers        = cfg.getParameter("media_servers", "");
    config.rtsp_interface_name  = cfg.getParameter("rtsp_interface_name", "rtsp");

    auto if_it = AmLcConfig::GetInstance().media_if_names.find(config.rtsp_interface_name);

    if (if_it == AmLcConfig::GetInstance().media_if_names.end()) {
        ERROR("RTSP media interface not found\n");
        return -1;
    }

    config.l_if = if_it->second;
    unsigned int addridx = 0;
    for(auto& info : AmLcConfig::GetInstance().media_ifs[config.l_if].proto_info) {
        if(info->mtype == MEDIA_info::RTSP) {
            config.l_ip = info->local_ip;
            config.laddr_if = addridx;
        }
        addridx++;
    }

    if (cfg.getParameter("use_dns_srv") == "yes")
        config.use_dns_srv = true;
    else
        config.use_dns_srv = false;

    if (!load_media_servers(config.media_servers)) {
        ERROR("Can't parse media_servers: %s\n", config.media_servers.c_str());
        return -1;
    }

    return 0;
}


int RtspClient::init()
{
    if ((epoll_fd = epoll_create1(0)) == -1
        || !TimerFD::init(epoll_fd, 1 * 1000 * 1000, -TIMER)
        || !EventFD::init(epoll_fd, EFD_SEMAPHORE, -EVENT) )
            return -1;

    init_connections();

    INFO("RtspClient initialized");

    return 0;
}


int RtspClient::onLoad()
{
    if (configure()) {
        ERROR("configuration error");
        return -1;
    }

    if (init()) {
        ERROR("initialization error");
        return -1;
    }

    start();

    return 0;
}


void RtspClient::postEvent(AmEvent* e)
{
    AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(e);

    if (sys_ev && sys_ev->sys_event == AmSystemEvent::ServerShutdown) {
        DBG("stopping RtspClient...");

        tostop = true;
        event_fire();
    }
}


void RtspClient::on_stop()
{
    tostop = true;
    event_fire();
}


void RtspClient::on_timer()
{
    uint64_t val = TimerFD::handler();

    for (auto& sess : rtsp_session)
        sess.on_timer(val);
}


void RtspClient::on_event()
{
    EventFD::handler();
}


bool RtspClient::link(int fd, int op, struct epoll_event &ev)
{
    int ret = epoll_ctl(epoll_fd, op, fd, &ev);

    if (ret)
        ERROR("epoll_ctl(): %m");

    return !ret;
}


void RtspClient::run()
{
    setThreadName("rtsp-client");

    AmEventDispatcher::instance()->addEventQueue(RTSP_EVENT_QUEUE, this);

    do {
        struct epoll_event events[EPOLL_MAX_EVENTS];

        int ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if (ret == -1 && errno != EINTR)
            ERROR("epoll_wait(): %m");

        if (ret < 1) {
            usleep(100000);
            continue;
        }

        for (int n=0; n < ret; ++n) {
            uint32_t ev         = events[n].events;
            int      ev_info    = events[n].data.fd;

            switch(ev_info) {
            case -TIMER : on_timer(); break;
            case -EVENT : on_event(); break;

            default: rtsp_session[ev_info].handler(ev);
            }
        }

    } while (!tostop);

    AmEventDispatcher::instance()->delEventQueue(RTSP_EVENT_QUEUE);

    DBG("RtspClient stopped");
}


RtspSession *RtspClient::media_server_lookup()
{
    for (auto& sess : rtsp_session)
        if (sess.get_state() == RtspSession::Active)
            return &sess;

    throw AmSession::Exception(500, "media_server_lookup failed");

    return nullptr;
}


uint64_t RtspClient::addStream(RtspAudio &audio)
{
    AmLock l(_streams_mtx);

    streams.insert(std::pair<uint64_t, RtspAudio*>(++id_counter, &audio));

    return id_counter;
}


void RtspClient::removeStream(uint64_t id)
{
    AmLock l(_streams_mtx);

    streams.erase(id);
}


/// TODO: we need failover for media servers
int RtspClient::RtspRequest(const RtspMsg &msg)
{
    RtspSession *sess = media_server_lookup();

    return sess->rtspSendMsg(msg);
}


void RtspClient::onRtspReply(const RtspMsg &msg)
{
    AmLock l(_streams_mtx);

    auto it = streams.find(msg.owner_id);

    if (it == streams.end())
        return;

    RtspAudio *audio = it->second;

    audio->onRtspMessage(msg);
}


void RtspClient::onRtspPlayNotify(const RtspMsg &msg)
{
    AmLock l(_streams_mtx);

#if 0
    for (auto& it : streams) {

        RtspAudio *audio = it.second;

        if (audio->getStreamID() == msg.streamid
            && audio->isPlaing()) {
                audio->onRtspPlayNotify(msg);
                break;
        }
    }
#endif
    auto it = std::find_if(
        std::begin(streams),std::end(streams),
        [&msg](RtspStreamMap::value_type &it) {
            return it.second->isPlaying() && it.second->getStreamID() == msg.streamid;
        });

    if(it != std::end(streams)) {
        it->second->onRtspPlayNotify(msg);
    } else {
        DBG("onRtspPlayNotify(): no matching RtspAudio instance in playing state for streamid: %d",
            msg.streamid);
    }
}

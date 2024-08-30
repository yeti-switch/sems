#include "RtspClient.h"
#include "AmSessionContainer.h"
#include "AmEventDispatcher.h"
#include "AmUtils.h"
#include "log.h"

#include <netdb.h>
#include <sys/epoll.h>
#include <cctype>
#include <algorithm>
#include <fstream>


#define MOD_NAME "rtsp_client"

#define EPOLL_MAX_EVENTS    256

#define PARAM_MAX_QUEUE_LENGTH_NAME     "max_queue_length"
#define PARAM_RECONNECT_INTERVAL_NAME   "reconnect_interval"
#define PARAM_SHUTDOWN_CODE_NAME        "shutdown_code"
#define PARAM_OPEN_TIMEOUT_NAME         "open_timeout"
#define PARAM_MEDIA_SERVERS_NAME        "media_servers"
#define PARAM_USE_DNS_SRV_NAME          "use_dns_srv"
#define PARAM_RTSP_INTERFACE_NAME_NAME  "rtsp_interface_name"

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
  : epoll_fd(-1), tostop(false), id_counter(0)
{
    _instance = this;
}


RtspClient::RtspClient(const string& name)
  : epoll_fd(-1), tostop(false), id_counter(0)
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
        ERROR("can't resolve destination: '%s'", host.c_str());
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


size_t RtspClient::load_media_servers(cfg_t* cfg)
{
    for (size_t i = 0; i < cfg_size(cfg, PARAM_MEDIA_SERVERS_NAME); i++) {
        string host = cfg_getnstr(cfg, PARAM_MEDIA_SERVERS_NAME, i);
        parse_host_str(host);
    }

    return media_nodes.size();
}


void RtspClient::init_connections()
{
    int active_connections = 0;

    for (auto& saddr : media_nodes) {
        auto &session = rtsp_session.emplace_back(this, saddr, active_connections++);
        rtsp_session_by_slot.push_back(&session);
    }
}

static void cfg_error_callback(cfg_t *cfg, const char *fmt, va_list ap)
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

int RtspClient::configure(const std::string& conf)
{
    cfg_opt_t cfg_opt[] ={
        CFG_INT(PARAM_MAX_QUEUE_LENGTH_NAME, 0, CFGF_NONE),
        CFG_INT(PARAM_RECONNECT_INTERVAL_NAME, 0, CFGF_NONE),
        CFG_INT(PARAM_SHUTDOWN_CODE_NAME, 503, CFGF_NONE),
        CFG_INT(PARAM_OPEN_TIMEOUT_NAME, 0, CFGF_NONE),
        CFG_STR_LIST(PARAM_MEDIA_SERVERS_NAME, 0, CFGF_NONE),
        CFG_BOOL(PARAM_USE_DNS_SRV_NAME, cfg_false, CFGF_NONE),
        CFG_STR(PARAM_RTSP_INTERFACE_NAME_NAME, "", CFGF_NODEFAULT),
        CFG_END()
    };

    cfg_t *cfg = cfg_init(cfg_opt, CFGF_NONE);
    if(!cfg) return -1;
    cfg_set_error_function(cfg, cfg_error_callback);
    switch(cfg_parse_buf(cfg, conf.c_str())) {
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

    config.max_queue_length     = cfg_getint(cfg, PARAM_MAX_QUEUE_LENGTH_NAME);
    config.reconnect_interval   = cfg_getint(cfg, PARAM_RECONNECT_INTERVAL_NAME);
    config.shutdown_code        = cfg_getint(cfg, PARAM_SHUTDOWN_CODE_NAME);
    config.open_timeout         = cfg_getint(cfg, PARAM_OPEN_TIMEOUT_NAME);
    AmLcConfig::instance().getMandatoryParameter(cfg, PARAM_RTSP_INTERFACE_NAME_NAME, config.rtsp_interface_name);

    int i = 0;
    config.l_if = -1;
    for(auto& intf : AmConfig.media_ifs) {
        if(intf.name == config.rtsp_interface_name) {
            config.l_if = i;
            break;
        } else {
            i++;
        }
    }

    if (config.l_if == -1) {
        ERROR("RTSP media interface not found");
        cfg_free(cfg);
        return -1;
    }

    unsigned int addridx = 0;
    config.lproto_id = -1;
    for(auto& info : AmConfig.media_ifs[config.l_if].proto_info) {
        if(info->mtype == MEDIA_info::RTSP) {
            config.l_ip = info->local_ip;
            config.lproto_id = addridx;
            break;
        }
        addridx++;
    }

    if(config.lproto_id == -1) {
        ERROR("RTSP addr interface not found");
        cfg_free(cfg);
        return -1;
    }

    config.use_dns_srv = cfg_getbool(cfg, PARAM_USE_DNS_SRV_NAME);

    if (!load_media_servers(cfg)) {
        ERROR("Can't parse media_servers");
        cfg_free(cfg);
        return -1;
    }

    cfg_free(cfg);
    return 0;
}


int RtspClient::init()
{
    if ((epoll_fd = epoll_create1(0)) == -1
        || !TimerFD::init(epoll_fd, 1 * 1000 * 1000, -TIMER)
        || !EventFD::init(epoll_fd, EFD_SEMAPHORE, -EVENT) )
            return -1;

    init_connections();

    DBG("RtspClient initialized");

    return 0;
}


int RtspClient::onLoad()
{
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

    AmLock _lock(_streams_mtx);
    for(auto& stream : streams)
        stream.second->checkState(config.open_timeout);
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

            default: rtsp_session_by_slot[ev_info]->handler(ev);
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

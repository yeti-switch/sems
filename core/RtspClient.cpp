#include "RtspClient.h"
#include "AmSessionContainer.h"
#include "AmEventDispatcher.h"
#include "log.h"

#include <netdb.h>
#include <sys/epoll.h>
#include <cctype>
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
    : tostop(false), active_connections(0), epoll_fd(-1)
{
    _instance = this;
}


RtspClient::RtspClient(const string& name)
      : tostop(false), active_connections(0), epoll_fd(-1)
{
    _instance = this;
}


RtspClient::~RtspClient()
{
    ::close(epoll_fd);

    for(int slot=0; slot<active_connections; ++slot)
        delete conn[slot];
}


bool RtspClient::srv_resolv(string host, int port, sockaddr_storage &_sa)
{
    dns_handle  _dh;


    if(config.use_dns_srv)
    {
        static string   rtsp_srv_prefix = string("_rtsp._tcp.");
        host = rtsp_srv_prefix + host;
    }


    if( resolver::instance()->resolve_name(host.c_str(), &_dh, &_sa, IPv4, dns_r_srv) < 0)
    {
        ERROR("can't resolve destination: '%s'\n", host.c_str());
        return false;
    }

    if(!config.use_dns_srv)
        am_set_port(&_sa, port ? port : RTSP_DEFAULT_PORT);

    return true;
}


void RtspClient::parse_host_str(const string& host_port)
{
    int                 port = RTSP_DEFAULT_PORT;
    string              host, port_str;
    vector<string>      p = explode(host_port, ":");


    if( p.size() == 1 )
        host = trim(p[0], " ");
    else if (p.size() == 2 )
    {
        host = trim(p[0], " ");
        port_str = trim(p[1], " ");
    }
    else
    {
        ERROR("Bad host param: %s", host_port.c_str());
        return ;
    }

    if(port_str.length())
        port = atoi(port_str.c_str());

    sockaddr_storage    saddr;

    if(srv_resolv(host, port, saddr))
        media_nodes.push_back(saddr);
}


size_t RtspClient::load_media_servers(const string& servers)
{
    vector<string> s=explode(servers, ";,");


    for( vector<string>::const_iterator it=s.begin(); it != s.end(); ++it )
        parse_host_str(*it);

    return media_nodes.size();
}


bool RtspClient::init_connections()
{
    for( vector<sockaddr_storage>::const_iterator it=media_nodes.begin();
         it != media_nodes.end();
         ++it )
    {
        if( active_connections < MEDIA_CONNECTION_MAX )
        {
            const sockaddr_storage &saddr = *it;

            conn[active_connections] = new MediaServer( this, saddr, active_connections );

            if( !conn[active_connections] )
            {
                ERROR("MediaConnection creation failed");
                return false;
            }

            ++active_connections;
        }
        else
        {
            ERROR("Too many MediaConnection, %d MAX", MEDIA_CONNECTION_MAX);
            return false;
        }
    }

    return true;
}


int RtspClient::configure()
{
    AmConfigReader cfg;

    if( cfg.loadFile(AmConfig::ModConfigPath + string(MOD_NAME ".conf")) )
        return -1;


    config.max_queue_length     = cfg.getParameterInt("max_queue_length", 0);
    config.reconnect_interval   = cfg.getParameterInt("reconnect_interval", 10);
    config.shutdown_code        = cfg.getParameterInt("shutdown_code", 503);
    config.media_servers        = cfg.getParameter("media_servers", "");
    config.rtsp_interface_name  = cfg.getParameter("rtsp_interface_name", "rtsp");


    map<string,unsigned short>::iterator if_it = AmConfig::RTP_If_names.find(config.rtsp_interface_name);

    if( if_it  == AmConfig::RTP_If_names.end() ) {
        ERROR("RTSP media interface not found\n");
        return -1;
    }

    config.l_if = if_it->second;
    config.l_ip = AmConfig::RTP_Ifs[if_it->second].LocalIP;

    if( cfg.getParameter("use_dns_srv") == "yes" )
        config.use_dns_srv = true;
    else
        config.use_dns_srv = false;

    if(!load_media_servers(config.media_servers))
    {
        ERROR("Can't parse media_servers: %s\n", config.media_servers.c_str());
        return -1;
    }

    return 0;
}


int RtspClient::init()
{
    if(    (epoll_fd = epoll_create1(0)) == -1
        || !TimerFD::init(epoll_fd, 1 * 1000 * 1000, -TIMER)
        || !EventFD::init(epoll_fd, EFD_SEMAPHORE, -EVENT) )
            return -1;

    if( !init_connections() )
        return -1;

    INFO("RtspClient initialized");
    return 0;
}


int RtspClient::onLoad()
{
    if(configure())
    {
        ERROR("configuration error");
        return -1;
    }

    if(init())
    {
        ERROR("initialization error");
        return -1;
    }
    start();

    return 0;
}


void RtspClient::postEvent(AmEvent* e)
{
    AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(e);


    if( sys_ev && sys_ev->sys_event == AmSystemEvent::ServerShutdown )
    {
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

    for(int slot=0; slot<active_connections; ++slot)
        conn[slot]->on_timer(val);
}


void RtspClient::on_event()
{
    EventFD::handler();
}


void RtspClient::run()
{
    setThreadName("rtsp-client");

    AmEventDispatcher::instance()->addEventQueue(RTSP_EVENT_QUEUE, this);

    do
    {
        struct epoll_event events[EPOLL_MAX_EVENTS];

        int ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);


        if(ret == -1 && errno != EINTR)
            ERROR("%s: epoll_wait(): %m", __func__);

        if(ret < 1)
        {
            usleep(100000);
            continue;
        }


        for( int n=0; n < ret; ++n )
        {
            uint32_t ev         = events[n].events;
            int      ev_info    = events[n].data.fd;


            switch(ev_info)
            {
                case -TIMER : on_timer(); break;
                case -EVENT : on_event(); break;

                default: conn[ev_info]->handler(ev);
            }
        }

    } while( !tostop );

    AmEventDispatcher::instance()->delEventQueue(RTSP_EVENT_QUEUE);

    DBG("RtspClient stopped");
}


// TODO:
MediaServer *RtspClient::media_server_lookup()
{
    if(conn[0] && conn[0]->get_state()== MediaServer::Active)
        return conn[0];

    return 0;
}


void RtspClient::addStream(RtspAudio &audio, const string &uri)
{
    AmLock l(_streams_mtx);

    std::pair<StreamIterator, bool> result;
    RtspStream                      *stream;

    result = streams.emplace(&audio,RtspStream(&audio, uri));

    stream = &result.first->second;

    if( result.second == true )
        DBG("####### %s INSERTED %s", __func__, uri.c_str());
    else
    {
        /** RtspStream already existed */
        stream->update(uri);
        DBG("####### %s UPDATED %s", __func__, uri.c_str());
    }

    if( (stream->server = media_server_lookup()) ) {
        CLASS_DBG("successfull media server lookup. send DESCRIBE");
        stream->describe();
    } else {
        CLASS_DBG("media server lookup failed. destroy stream");
        streams.erase(result.first);
    }
}


void RtspClient::removeStream(RtspAudio &audio)
{
    AmLock l(_streams_mtx);

    StreamIterator  sit = streams.find(&audio);

    if( sit != streams.end() )
    {
        RtspStream *stream = &sit->second;
        DBG("####### %s stream %p", __func__, stream);
        stream->close();
        streams.erase(sit);
    }
}

bool RtspClient::link(int fd, int op, struct epoll_event &ev)
{
    int ret = epoll_ctl(epoll_fd, op, fd, &ev);

    if(ret != -1)
        return true;

    ERROR("epoll_ctl(): %m");
    return false;
}

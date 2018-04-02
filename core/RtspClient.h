#pragma once

#include "eventfd.h"
#include "timerfd.h"
#include "RtspAudio.h"
#include "AmApi.h"
#include "AmSession.h"
#include "AmEventFdQueue.h"
#include <sip/resolver.h>
#include "RtspConnection.h"
#include "RtspAudio.h"

#include <vector>
using std::vector;
#include <string>
using std::string;
#include <map>
using std::map;

using namespace Rtsp;

#define RTSP_EVENT_QUEUE    "rtsp"
#define RTSP_DEFAULT_PORT   8554


struct RtspNoFileEvent
  : public AmEvent
{
    string          uri;
    RtspNoFileEvent(string &_uri) : AmEvent(0), uri(_uri) {}
};


class RtspClient : public AmThread, public AmEventQueueInterface,
                   private EventFD, TimerFD
{
        typedef enum {
            TIMER = 1,
            EVENT,
        } ctrl_t;

        typedef struct {
            int         l_if;
            string      l_ip;
            string      rtsp_interface_name;
            string      media_servers;
            bool        use_dns_srv;
            int         reconnect_interval;
            int         shutdown_code;
            unsigned int max_queue_length;
        } config_t;

        typedef std::map<uint64_t, RtspAudio*>      RtspStreamMap;
        typedef std::vector<RtspSession>            RtspServerVector;

        AmMutex                     _streams_mtx;
        RtspStreamMap               streams;
        RtspServerVector            servers;

        int                         epoll_fd;

        static RtspClient*          _instance;
        bool                        tostop;

        config_t                    config;
        vector<sockaddr_storage>    media_nodes;
        vector<RtspSession>         rtsp_session;
        uint64_t                    id_counter;

        RtspClient();
        ~RtspClient();

        void on_timer();
        void on_event();

        bool        srv_resolv(string host, int port, sockaddr_storage &_sa);
        void        parse_host_str(const string& host_port);
        size_t      load_media_servers(const string& servers);
        void        init_connections();
        RtspSession *media_server_lookup();

        int         configure();
        int         init();
        void        event_fire() { EventFD::pushEvent(); }

public:
        RtspClient(const string& name);
        static RtspClient *instance();
        static void dispose();

        int         shutdown_code() { return config.shutdown_code; }
        const string& localMediaIP() { return config.l_ip; }
        int         getRtpInterface() { return config.l_if; }
        int         getReconnectInterval() { return config.reconnect_interval; }

        uint64_t    addStream(RtspAudio &audio);
        void        removeStream(uint64_t id);

        void        RtspRequest(const RtspMsg &msg);
        void        onRtspPlayNotify(const RtspMsg &msg);
        void        onRtspReplay(const RtspMsg &msg);


        bool        link(int fd, int op, struct epoll_event &ev);
        uint64_t    get_timer_val() { return  val();}

        int onLoad();

        void run();
        void on_stop();
        void postEvent(AmEvent* e);
};

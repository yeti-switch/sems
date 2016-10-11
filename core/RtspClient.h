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
#include <deque>
using std::deque;

#define RTSP_EVENT_QUEUE "rtsp"


struct PlayList {
    typedef enum {
        New = 0,
        Pending,
    } msg_state_t;

    msg_state_t     state;
    uint32_t        seq;
    string          local_tag;
    string          url;

    PlayList(string _local_tag, string _url):
        state(New), seq(0), local_tag(_local_tag), url(_url) {}
};


struct RtspNoFileEvent
  : public AmEvent
{
    string          uri;
    RtspNoFileEvent(string &_uri) : AmEvent(0), uri(_uri) {}
};


struct RtspEvent
  : public AmEvent
{
    map<string, string> params;


    RtspEvent(map<string, string> &_params)
    : AmEvent(0)
    {
        std::copy(_params.begin(), _params.end(), std::inserter(params, params.end()) );
    }

    RtspEvent()
    : AmEvent(0)
    {}

};


#define MEDIA_CONNECTION_MAX        8
#define RTSP_DEFAULT_PORT           8554


class RtspClient : public AmThread, public AmEventQueueInterface,
                   private EventFD, TimerFD
{
        typedef enum {
            TIMER = 1,
            EVENT,
        } ctrl_t;

        typedef std::vector<MediaServer>            RtspServerVector;
        typedef RtspServerVector::iterator          MediaServerIterator;
        typedef std::map<RtspAudio *, RtspStream>   RtspStreamMap;
        typedef RtspStreamMap::iterator             StreamIterator;

        AmMutex                                     _streams_mtx;
        RtspStreamMap                               streams;


        RtspServerVector                            servers;


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

    int                         epoll_fd;

    static RtspClient*          _instance;
    bool                        tostop;

    config_t                    config;
    vector<sockaddr_storage>    media_nodes;


    int                         active_connections;
    MediaServer                 *conn[MEDIA_CONNECTION_MAX];

    protected:
        RtspClient();
        ~RtspClient();
        void on_timer();
        void on_event();

        bool        srv_resolv(string host, int port, sockaddr_storage &_sa);
        void        parse_host_str(const string& host_port);
        size_t      load_media_servers(const string& servers);
        bool        init_connections();
        MediaServer *media_server_lookup();

        int         configure();
        int         init();

public:
        int         shutdown_code() { return config.shutdown_code; }
        const string& localMediaIP() { return config.l_ip; }
        int         getRtpInterface() { return config.l_if; }

        void        event_fire() { EventFD::pushEvent(); }

        void        addStream(RtspAudio &audio, const string &uri);
        void        removeStream(RtspAudio &audio);
        bool        link(int fd, int op, struct epoll_event &ev);
        uint64_t    get_timer_val() { return  val();}

        RtspClient(const string& name);
        static RtspClient *instance();
        static void dispose();

        int onLoad();

        void run();
        void on_stop();
        void postEvent(AmEvent* e);
};



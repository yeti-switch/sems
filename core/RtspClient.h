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

#define RTSP_EVENT_QUEUE  "rtsp"
#define RTSP_DEFAULT_PORT 8554

#define RTSP_NO_FILE_ID 0
#define RTSP_TIMEOUT_ID 1

struct RtspNoFileEvent : public AmEvent {
    string uri;
    RtspNoFileEvent(string &_uri)
        : AmEvent(RTSP_NO_FILE_ID)
        , uri(_uri)
    {
    }
};

struct RtspTimeoutEvent : public AmEvent {
    string uri;
    RtspTimeoutEvent(const string &_uri)
        : AmEvent(RTSP_TIMEOUT_ID)
        , uri(_uri)
    {
    }
};

class RtspClient : public AmThread, public AmEventQueueInterface, private EventFD, TimerFD {
    typedef enum {
        TIMER = 1,
        EVENT,
    } ctrl_t;

    typedef struct {
        int          l_if;
        int          lproto_id;
        string       l_ip;
        string       rtsp_interface_name;
        string       media_servers;
        bool         use_dns_srv;
        int          reconnect_interval;
        int          shutdown_code;
        int          open_timeout;
        unsigned int max_queue_length;
    } config_t;

    typedef std::map<uint64_t, RtspAudio *> RtspStreamMap;
    typedef std::vector<RtspSession>        RtspServerVector;

    AmMutex          _streams_mtx;
    RtspStreamMap    streams;
    RtspServerVector servers;

    int epoll_fd;

    static RtspClient *_instance;
    bool               tostop;

    config_t                 config;
    vector<sockaddr_storage> media_nodes;
    list<RtspSession>        rtsp_session;
    vector<RtspSession *>    rtsp_session_by_slot;
    uint64_t                 id_counter;

    RtspClient();
    ~RtspClient();

    void on_timer();
    void on_event();

    bool         srv_resolv(string host, int port, sockaddr_storage &_sa);
    void         parse_host_str(const string &host_port);
    size_t       load_media_servers(cfg_t *cfg);
    void         init_connections();
    RtspSession *media_server_lookup();

    int  init();
    void event_fire() { EventFD::pushEvent(); }

  public:
    RtspClient(const string &name);
    static RtspClient *instance();

    int configure(const std::string &config);

    static void   dispose();
    int           shutdown_code() { return config.shutdown_code; }
    const string &localMediaIP() { return config.l_ip; }
    int           getRtpInterface() { return config.l_if; }
    int           getRtpProtoId() { return config.lproto_id; }
    int           getReconnectInterval() { return config.reconnect_interval; }

    uint64_t addStream(RtspAudio &audio);
    void     removeStream(uint64_t id);

    int  RtspRequest(const RtspMsg &msg);
    void onRtspPlayNotify(const RtspMsg &msg);
    void onRtspReply(const RtspMsg &msg);


    bool     link(int fd, int op, struct epoll_event &ev);
    uint64_t get_timer_val() { return val(); }

    int onLoad();

    void run();
    void on_stop();
    void postEvent(AmEvent *e);
};

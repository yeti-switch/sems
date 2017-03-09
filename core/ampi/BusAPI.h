#pragma once

#include "eventfd.h"
#include "timerfd.h"
#include "AmApi.h"
#include "AmSession.h"
#include "AmEventFdQueue.h"
#include <singleton.h>

#include <string>
#include <map>
#include <deque>
#include <vector>

using std::deque;
using std::map;
using std::string;
using std::vector;


#define BUS_CONNECTION_MAX              4

class BusConnection;


struct BusMsg {
    typedef enum {
        New = 0,
        Pending,
    } msg_state_t;

    msg_state_t     state;
    uint32_t        seq;
    string          local_tag;
    string          application_method;
    string          body;
    uint64_t        updated;

    BusMsg(string _local_tag, string _application_method, string _body)
        : state(New), seq(0),
          local_tag(_local_tag),
          application_method(_application_method),
          body(_body) {}

    ~BusMsg() {}
};

/*
struct BusEvent
  : public AmEvent
{
  string session_id;
  struct timeval created_at;
  string    values_hash;

  enum BusEventType {
    Auth = 0,
    Accounting
  };

  BusEvent( string session_id,  string values)
    : AmEvent(Auth),
      session_id(session_id),
      values_hash(values)
  {
      gettimeofday(&created_at,NULL);
  }
};*/

struct BusReplyEvent
  : public AmEvent
{
    enum BusResult {
        Success,
        Error
    } result;

    map<string, string> params;
    AmArg data;

    BusReplyEvent(BusResult  result, map<string, string> &_params)
    : AmEvent(0),
      result(result)
    {
        std::copy(_params.begin(), _params.end(), std::inserter(params, params.end()) );
    }

    BusReplyEvent(BusResult  result, const AmArg &data)
    : AmEvent(0),
      result(result),
      data(data)
    { }

    BusReplyEvent(BusResult  result, map<string, string> &_params, const AmArg &data)
    : AmEvent(0),
      result(result),
      data(data)
    {
        std::copy(_params.begin(), _params.end(), std::inserter(params, params.end()) );
    }

    BusReplyEvent()
    : AmEvent(0),
      result(Success)
    {}

};



class BusClient :   public AmPluginFactory, public AmThread,
                    public AmEventQueueInterface,
                    private EventFD, TimerFD
{
    typedef enum {
        TIMER = 1,
        EVENT,
    } ctrl_t;

    typedef struct {
        string      bus_nodes;
        int         node_id;
        int         reconnect_interval;
        int         shutdown_code;
        unsigned int max_queue_length;
    } config_t;

    int                         epoll_fd;
    static BusClient*           _instance;
    bool                        tostop;
    config_t                    config;

    AmMutex                     queue_mtx;
    deque<BusMsg *>             pending_queue;

    vector<sockaddr_storage>    bus_nodes;

    int                         active_connections;
    BusConnection               *conn[BUS_CONNECTION_MAX];


    protected:
        BusClient();
        ~BusClient();

        void    on_timer();
        void    on_event();

        void    parse_host_str(const string& host_port);
        size_t  load_bus_nodes(const string& servers);
        bool    init_connections();
        int     configure();
        int     init();

public:
    int get_node_id() { return config.node_id; }
    void event_fire() { EventFD::pushEvent(); }
    bool link(int fd, int op, struct epoll_event &ev);
    uint64_t    get_timer_val() { return  val();}

    void postBusMsg(BusMsg *msg);

    BusClient(const string& name);
    static BusClient *instance();

    int onLoad();

    void run();
    void on_stop();
    void dispose() {}
    void postEvent(AmEvent* e);
};

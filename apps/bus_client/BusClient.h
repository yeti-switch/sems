#pragma once

#include "sems.h"
#include "ampi/BusAPI.h"
#include "AmThread.h"
#include "AmApi.h"
#include "RpcTreeHandler.h"

#include "connection.h"

#define BUS_DEFAULT_PORT                30000
#define BUS_DISPATCHER_MAX_EPOLL_EVENT  256
#define TIMER_INTERVAL_SEC              1
#define BUS_CONNECTION_MAX              4

#include <deque>
#include <vector>
#include <unordered_map>
#include <memory>
#include <algorithm>

using std::deque;
using std::vector;
using std::multimap;

class BusClient;

class BusDynamicQueue
  : public AmEventFdQueue,
    public AmEventHandler
{
    string queue_name;
    string application;
    BusClient *bus;

  public:
    BusDynamicQueue(
        BusClient *bus,
        const string &queue_name,
        const string &application)
      : AmEventFdQueue(this),
        queue_name(queue_name),
        application(application),
        bus(bus)
    {}
    ~BusDynamicQueue() {}

    void process(AmEvent* ev);
    string &getQueueName() { return queue_name; }
};

class BusClient
  : public AmDynInvokeFactory,
    public AmConfigFactory,
    public RpcTreeHandler<BusClient>,
    public AmThread,
    public AmEventFdQueue,
    public AmEventHandler
{
    typedef enum {
        TIMER = 1,
        EVENT,
    } ctrl_t;

    typedef enum {
        CONN_OK = 0,
        CONN_ERROR,
        CONN_WARNING
    } send_conn_result_t;

    AmTimerFd timer;
    uint64_t  timer_val;
    AmTimerFd query_timer;
    uint64_t  query_timer_val;

    AmEventFd stop_event;
    AmCondition<bool> stopped;

    typedef std::unordered_map<int, std::unique_ptr<BusDynamicQueue> > DynamicQueuesMap;
    DynamicQueuesMap dynamic_queues;

    typedef struct {
        int         so_rcvbuf;
        int         so_sndbuf;
        int         reconnect_interval;
        int         query_timeout;
        int         shutdown_code;
        struct dynamic_queue_config_t {
            string name;
            string application;
        };
        vector<dynamic_queue_config_t> dynamic_queues;
    } config_t;

    typedef struct {
        int priority;
        int weight;
        string name_conn;
        BusConnection* conn;
    } route_conn_params_t;

    typedef struct {
        string name;
        bool broadcast;
    } route_method_param_t;

    //mapping by weight
    using route_methods_balancing_group_t = multimap<int, route_conn_params_t>;
    //mapping by priority
    using route_method_t = map<int,route_methods_balancing_group_t>;

    using route_methods_container = list<pair<route_method_param_t, route_method_t>>;

    typedef struct {
        uint64_t query_time;
        uint32_t timeout;
        BusMsg   *msg;
    } bus_query_param_t;

    using bus_query_map = map<int, bus_query_param_t>;

    int                         epoll_fd;
    bool                        tostop;
    config_t                    config;

    map<string, sockaddr_storage>   bus_nodes;
    map<string, int>   bus_nodes_index;
    route_methods_container route_methods;

    route_methods_container::const_iterator matchRouteMethod(const string &app_method);

    int                         active_connections;
    BusConnection               *conn[BUS_CONNECTION_MAX];

    bus_query_map               query_map;

    static BusClient *_instance;

    void fillRouteInfo(AmArg &route, const route_methods_container::value_type &route_data);
    send_conn_result_t sendMessagetoConnection(BusConnection* c, BusMsg* msg);

    rpc_handler postEventHdl;
    rpc_handler showConnections;
    rpc_handler showRoutes;
    rpc_handler requestRoutesTest;

  protected:
    BusClient();
    ~BusClient();

    void on_timer();
    void on_timer_query();

    bool init_connections();
    bool init_routing();
    void init_rpc_tree();
    int init();

  public:

    AmDynInvoke* getInstance() { return instance(); }
    int configure(const string& config);
    int reconfigure(const string& config);

    bool link(int fd, int op, struct epoll_event &ev);
    uint64_t    get_timer_val() { return timer_val;}

    void sendMsg(BusMsg *msg);
    void process(AmEvent* ev);

    BusClient(const string& name);
    static BusClient *instance();

    int onLoad();

    void on_query_response(uint32_t seq);

    void run();
    void on_stop();
    void dispose() {}
};

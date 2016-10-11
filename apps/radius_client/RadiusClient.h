#pragma once

#include "ampi/RadiusClientAPI.h"
#include "RadiusAuthConnection.h"
#include "RadiusAccConnection.h"

#include "AmApi.h"
#include "AmEventDispatcher.h"

#include "AmEventFdQueue.h"

#include <string>
#include <map>
using std::string;
using std::map;

class RadiusClient
: public AmDynInvokeFactory,
  public AmThread,
  public AmEventFdQueue,
  public AmEventHandler,
  public AmDynInvoke
{
    static RadiusClient* _instance;

    typedef map<unsigned int, RadiusConnection *> Connections;
    Connections sock2connection;
    AmMutex connections_mutex;

    typedef map<unsigned int, RadiusAuthConnection *> AuthConnections;
    AuthConnections auth_connections;

    typedef map<unsigned int, RadiusAccConnection *> AccConnections;
    AccConnections acc_connections;

    AmEventFd stop_event;
    AmTimerFd timer;
    AmCondition<bool> stopped;

    int epoll_fd;

  public:
    RadiusClient(const string& name);
    ~RadiusClient();

    static RadiusClient* instance();
    AmDynInvoke* getInstance() { return instance(); }

    void invoke(const string& method,
                const AmArg& args, AmArg& ret);
    int onLoad();
    int init();

    void run();
    void on_stop();

    void process(AmEvent* ev);
    void check_timeouts();
    void on_packet(int sock);

    /* auth */

    void onRadiusAuthRequest(const RadiusRequestEvent &req);
    int addAuthConnection(
        unsigned int connection_id,
        string name,
        string server,
        unsigned short port,
        string secret,
        bool reject_on_error,
        unsigned int timeout_msec,
        unsigned int attempts,
        AmArg avps);
    void clearAuthConnections();
    void showAuthConnections(const AmArg &args, AmArg &ret);
    void showAuthStat(const AmArg &args, AmArg &ret);

    /* accounting */

    void getAccRules(const AmArg &args, AmArg &ret);
    void onRadiusAccRequest(const RadiusRequestEvent &req);
    int addAccConnection(
        unsigned int connection_id,
        string name,
        string server,
        unsigned short port,
        string secret,
        unsigned int timeout_msec,
        unsigned int attempts,
        AmArg start_avps,
        AmArg interim_avps,
        AmArg stop_avps,
        bool enable_start_accounting,
        bool enable_interim_accounting,
        bool enable_stop_accounting,
        int interim_accounting_interval);
    void clearAccConnections();
    void showAccConnections(const AmArg &args, AmArg &ret);
    void showAccStat(const AmArg &args, AmArg &ret);

};


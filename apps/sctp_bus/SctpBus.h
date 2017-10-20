#pragma once

#include "ampi/SctpBusAPI.h"
#include "SctpConnection.h"
#include "SctpServerConnection.h"
#include "config.h"

#include "AmApi.h"
#include "AmEventDispatcher.h"
#include "AmEventFdQueue.h"

#include <stdint.h>

#include <string>
#include <map>
#include "RpcTreeHandler.h"

using std::string;
using std::map;

class SctpBus
: public AmDynInvokeFactory,
  public AmThread,
  public AmEventFdQueue,
  public AmEventHandler,
  public RpcTreeHandler<SctpBus>
{
    static SctpBus* _instance;

    typedef map<unsigned int, SctpConnection *> Connections;
    Connections connections_by_sock;
    Connections connections_by_id;

    SctpServerConnection server_connection;

    AmEventFd stop_event;
    AmTimerFd timer;
    AmCondition<bool> stopped;

    int epoll_fd;

  protected:
    void init_rpc_tree();

  public:
    SctpBus(const string& name);
    ~SctpBus();

    static SctpBus* instance();
    AmDynInvoke* getInstance() { return SctpBus::instance(); }

    int onLoad();
    int configure();

    void run();
    void on_stop();

    void process(AmEvent* ev);
    void on_timer();
    void process_client_connection(int sock, uint32_t events);

    void onSendEvent(const SctpBusSendEvent &e);
    void onReloadEvent();

    //client connections management
    int addClientConnection(unsigned int id,
                            sockaddr_storage &a,
                            int reconnect_interval);

    void showServerAssocations(const AmArg &args, AmArg &ret);
    void showClientConnections(const AmArg &args, AmArg &ret);
    void reload(const AmArg &args, AmArg &ret);
};


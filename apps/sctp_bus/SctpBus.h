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

#define MOD_NAME "sctp_bus"

class SctpBus
: public AmDynInvokeFactory,
  public AmConfigFactory,
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
    cfg_reader reader;

    AmEventFd stop_event;
    AmTimerFd timer;
    AmCondition<bool> stopped;

    int epoll_fd;

  protected:
    void init_rpc_tree();
    int configure();

  public:
    SctpBus(const string& name);
    ~SctpBus();

    static SctpBus* instance();
    AmDynInvoke* getInstance() { return SctpBus::instance(); }

    int onLoad();
    int configure(const std::string& config);
    int reconfigure(const std::string& config);

    void run();
    void on_stop();

    void process(AmEvent* ev);
    void on_timer();
    void process_client_connection(int sock, uint32_t events);

    void onSendEvent(const SctpBusSendEvent &e);
    void onSendRawRequest(const SctpBusRawRequest &e);
    void onSendRawReply(const SctpBusRawReply &e);
    void onConnectionAdd(const SctpBusAddConnection &e);
    void onConnectionRemove(const SctpBusRemoveConnection &e);
    void onReloadEvent();

    //client connections management
    int addClientConnection(unsigned int id,
                            const sockaddr_storage &a,
                            int reconnect_interval,
                            const string &event_sink = string());

    void showServerAssocations(const AmArg &args, AmArg &ret);
    void showClientConnections(const AmArg &args, AmArg &ret);
    void reload(const AmArg &args, AmArg &ret);
};


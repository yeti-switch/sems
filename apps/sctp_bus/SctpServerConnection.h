#pragma once

#include "SctpConnection.h"
#include "AmThread.h"

class SctpServerConnection
  : public SctpConnection
{
    struct client_info {
        string host;
        short unsigned int port;
        int last_node_id;
        unsigned long events_received;
        client_info(const string &host, short unsigned int port)
          : host(host),
            port(port),
            last_node_id(-1),
            events_received(0)
        {}
    };
    typedef std::map<int,client_info> ClientsMap;
    ClientsMap clients;
    AmMutex clients_mutex;
    FunctionCounter& server_clients;
    static SctpServerConnection* instance;

  public:
    SctpServerConnection() :
      server_clients(stat_group(Counter, MOD_NAME, "connections")
                     .setHelp("count of sctp server connections")
                     .addFunctionCounter([]()->unsigned long long{
                       AmLock lock(instance->clients_mutex);
                       return instance->clients.size();
                    })){ instance = this; }
    int init(int efd, const sockaddr_storage &a);

    int process(uint32_t events) override;
    void handle_notification(const sockaddr_storage &from) override;
    int on_timer(time_t) override { return 0; }

    void getInfo(AmArg &ret) override;
};

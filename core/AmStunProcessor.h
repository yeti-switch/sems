#pragma once

#include "sip/wheeltimer.h"
#include "sip/sa_storage_transport_key.h"
#include "hash_table.h"
#include "singleton.h"

#include <unordered_map>

class IceContext;
class AmStunConnection;

class AmStunProcessor
  : public AmThread
{
    int epoll_fd;
    AmTimerFd timer;
    bool stopped;

    std::unordered_map<AmStunConnection *, unsigned long long> connections;
    std::vector<IceContext*> contexts;
    AmMutex connections_mutex;

    void on_timer();

  protected:
    AmStunProcessor();
    virtual ~AmStunProcessor();

  public:
    void add_ice_context(IceContext* context);
    void remove_ice_context(IceContext* context);
    void set_timer(AmStunConnection *connection, unsigned long long timeout);
    void remove_timer(AmStunConnection *connection);

    void run() override;
    void on_stop() override;

    void dispose();
};

typedef singleton<AmStunProcessor> stun_processor;

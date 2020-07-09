#pragma once

#include "sip/wheeltimer.h"
#include "sip/sa_storage_transport_key.h"
#include "hash_table.h"
#include "singleton.h"

#include <unordered_map>

#define STUN_PEER_HT_POWER 6
#define STUN_PEER_HT_SIZE  (1 << STUN_PEER_HT_POWER)
#define STUN_PEER_HT_MASK  (STUN_PEER_HT_SIZE - 1)

/**
 * Blacklist bucket: key type
 */
typedef sa_storage_transport_key<STUN_PEER_HT_MASK> sp_addr;

class AmStunConnection;

typedef ht_map_bucket<sp_addr,AmStunConnection,
                      ht_fake<AmStunConnection>,
                      sp_addr::less> sp_bucket_base;

typedef hash_table<sp_bucket_base> stun_pair_ht;

class AmStunProcessor
  : public AmThread
{
    int epoll_fd;
    AmTimerFd timer;
    bool stopped;

    std::unordered_map<AmStunConnection *, unsigned long long> connections;
    AmMutex connections_mutex;

    struct set_timer_event {
        AmStunConnection *connection;
        unsigned long long timeout;
        set_timer_event(AmStunConnection *connection, unsigned long long timeout = 0)
          : connection(connection),
            timeout(timeout)
        {}
    };
    std::list<set_timer_event> set_timer_events;
    AmMutex set_timer_events_mutex;

    void on_timer();

  protected:
    AmStunProcessor();
    virtual ~AmStunProcessor();

  public:
    void set_timer(AmStunConnection *connection, unsigned long long timeout);
    void remove_timer(AmStunConnection *connection);

    void run() override;
    void on_stop() override;

    void dispose();
};

typedef singleton<AmStunProcessor> stun_processor;

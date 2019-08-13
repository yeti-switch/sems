#ifndef AM_STUN_PROCESSOR_H
#define AM_STUN_PROCESSOR_H

#include "sip/wheeltimer.h"
#include "sip/addr_struct.h"
 #include "hash_table.h"
#include "singleton.h"

#define STUN_PEER_HT_POWER 6
#define STUN_PEER_HT_SIZE  (1 << STUN_PEER_HT_POWER)
#define STUN_PEER_HT_MASK  (STUN_PEER_HT_SIZE - 1)

/**
 * Blacklist bucket: key type
 */
typedef addr<STUN_PEER_HT_MASK> sp_addr;
typedef addr_less<STUN_PEER_HT_MASK> sp_addr_less;

class AmStunConnection;

typedef ht_map_bucket<sp_addr,AmStunConnection,
		      ht_fake<AmStunConnection>,
		      sp_addr_less> sp_bucket_base;

typedef hash_table<sp_bucket_base> stun_pair_ht;

class AmStunProcessor : public stun_pair_ht
{
protected:
    AmStunProcessor();
    virtual ~AmStunProcessor();

public:
    template <typename RetFunc>
    void dump(RetFunc f) { stun_pair_ht::dump(f); }
    bool exist(const sockaddr_storage* addr);
    void insert(const sockaddr_storage* addr, AmStunConnection* conn);
    void remove(const sockaddr_storage* addr);

    void fire(const sockaddr_storage* addr);
};

typedef singleton<AmStunProcessor> stun_processor;

#endif/*AM_STUN_PROCESSOR_H*/

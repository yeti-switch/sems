#ifndef _tr_blacklist_h_
#define _tr_blacklist_h_

#include "hash_table.h"
#include "singleton.h"

#include "ip_util.h"
#include "wheeltimer.h"
#include "sa_storage_transport_key.h"
#include <AmArg.h>

#define BLACKLIST_HT_POWER 6
#define BLACKLIST_HT_SIZE  (1 << BLACKLIST_HT_POWER)
#define BLACKLIST_HT_MASK  (BLACKLIST_HT_SIZE - 1)

/**
 * Blacklist bucket: key type
 */
typedef sa_storage_transport_key<BLACKLIST_HT_MASK> bl_addr;

struct bl_entry;

typedef ht_map_bucket<bl_addr, bl_entry, ht_delete<bl_entry>, bl_addr::less> bl_bucket_base;

class blacklist_bucket : public bl_bucket_base {
  protected:
    bool insert(const bl_addr &k, bl_entry *v) { return bl_bucket_base::insert(k, v); }

  public:
    blacklist_bucket(unsigned long id)
        : bl_bucket_base(id)
    {
    }

    bool insert(const bl_addr &addr, unsigned int duration /* ms */, const char *reason);
    bool remove(const bl_addr &addr);
};

typedef blacklist_bucket::value_map::iterator blacklist_elmt;

struct bl_timer : public timer {
    bl_addr addr;

    bl_timer() = delete;

    bl_timer(const bl_addr &addr, unsigned int expires)
        : timer(expires)
        , addr(addr)
    {
    }

    void fire();
};

/**
 * Blacklist bucket: value type
 */
struct bl_entry {
    bl_timer *t;

    bl_entry() {}

    bl_entry(bl_timer *t)
        : t(t)
    {
    }
};

typedef hash_table<blacklist_bucket> blacklist_ht;

class _tr_blacklist : protected blacklist_ht {
  protected:
    _tr_blacklist();
    ~_tr_blacklist();
    void dispose() {}

  public:
    // public blacklist API:
    template <typename RetFunc> void dump(RetFunc f) { hash_table<blacklist_bucket>::dump(f); }
    bool                             exist(const sockaddr_storage *addr);
    void insert(const sockaddr_storage *addr, unsigned int duration /* ms */, const char *reason);
    void remove(const sockaddr_storage *addr);
};

typedef singleton<_tr_blacklist> tr_blacklist;

#endif

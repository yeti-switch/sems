#include "tr_blacklist.h"
#include <string.h>

#include "hash.h"

#define DBG_BL INFO

void bl_timer::fire()
{
  DBG_BL("blacklist: %s/%i expired",
	 am_inet_ntop(&addr).c_str(),am_get_port(&addr));
  tr_blacklist::instance()->remove(&addr);
}

bool blacklist_bucket::insert(const bl_addr& addr, unsigned int duration /* ms */,
			      const char* reason)
{
  wheeltimer* wt = wheeltimer::instance();
  unsigned int expires = duration / (TIMER_RESOLUTION/1000);
  expires += wt->wall_clock;

  bl_timer* t = new bl_timer(addr,expires);
  bl_entry* bl_e = new bl_entry(t);

  if(!bl_bucket_base::insert(addr,bl_e)) {
    delete t;
    return false;
  }

  DBG_BL("blacklist: added %s/%i (%s/TTL=%.1fs)",
	 am_inet_ntop(&addr).c_str(),am_get_port(&addr),
	 reason,(float)duration/1000.0);

  wt->insert_timer(t);
  return true;
}

bool blacklist_bucket::remove(const bl_addr& addr)
{
  value_map::iterator it = find(addr);

  if(it != elmts.end()){
    bl_entry* v = it->second;
    wheeltimer::instance()->remove_timer(v->t);
    elmts.erase(it);
    allocator().dispose(v);
    return true;
  }

  return false;
}

_tr_blacklist::_tr_blacklist()
  : blacklist_ht(BLACKLIST_HT_SIZE)
{
}

_tr_blacklist::~_tr_blacklist()
{ 
}

bool _tr_blacklist::exist(const sockaddr_storage* addr)
{
  bool res;
  blacklist_bucket* bucket = get_bucket(hashlittle(addr, SA_len(addr), 0)
					& BLACKLIST_HT_MASK);
  bucket->lock();
  res = bucket->exist(*(const bl_addr*)addr);
  bucket->unlock();

  return res;
}

void _tr_blacklist::insert(const sockaddr_storage* addr, unsigned int duration,
			   const char* reason)
{
  if(!duration)
    return;

  blacklist_bucket* bucket = get_bucket(hashlittle(addr, SA_len(addr), 0)
					& BLACKLIST_HT_MASK);
  bucket->lock();
  if(!bucket->exist(*(const bl_addr*)addr)) {
    bucket->insert(*(const bl_addr*)addr,duration,reason);
  }
  bucket->unlock();
}

void _tr_blacklist::remove(const sockaddr_storage* addr)
{
  blacklist_bucket* bucket = get_bucket(hashlittle(addr, SA_len(addr), 0)
					& BLACKLIST_HT_MASK);
  bucket->lock();
  bucket->remove(*(const bl_addr*)addr);
  bucket->unlock();
}

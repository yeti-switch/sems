#include "AmStunProcessor.h"
#include "AmStunConnection.h"
#include "AmUtils.h"
#include "sip/ip_util.h"

AmStunProcessor::AmStunProcessor()
: stun_pair_ht(STUN_PEER_HT_SIZE)
{
}

AmStunProcessor::~AmStunProcessor()
{
}

bool AmStunProcessor::exist(const sockaddr_storage* addr)
{
  bool res;
  sp_bucket_base* bucket = get_bucket(hashlittle(addr, SA_len(addr), 0)
					& STUN_PEER_HT_MASK);
  bucket->lock();
  res = bucket->exist(*(const sp_addr*)addr);
  bucket->unlock();

  return res;
}

void AmStunProcessor::insert(const sockaddr_storage* addr, AmStunConnection* conn)
{
  DBG("AmStunProcessor::insert(%s,%p)", get_addr_str(addr).data(), conn);
  sp_bucket_base* bucket = get_bucket(hashlittle(addr, SA_len(addr), 0)
					& STUN_PEER_HT_MASK);
  bucket->lock();
  if(!bucket->exist(*(const sp_addr*)addr)) {
    bucket->insert(*(const sp_addr*)addr,conn);
  }
  bucket->unlock();
}

void AmStunProcessor::remove(const sockaddr_storage* addr)
{
  DBG("AmStunProcessor::remove(%s)", get_addr_str(addr).data());
  sp_bucket_base* bucket = get_bucket(hashlittle(addr, SA_len(addr), 0)
					& STUN_PEER_HT_MASK);
  bucket->lock();
  bucket->remove(*(const sp_addr*)addr);
  bucket->unlock();
}

void AmStunProcessor::fire(const sockaddr_storage* addr)
{
  DBG("AmStunProcessor::fire(%s)", get_addr_str(addr).data());
  sp_bucket_base* bucket = get_bucket(hashlittle(addr, SA_len(addr), 0)
					& STUN_PEER_HT_MASK);
  bucket->lock();
  auto c = bucket->get(addr);
  if(c) {
    c->send_request();
  }
  bucket->unlock();
}


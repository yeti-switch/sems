#ifndef ADDR_STRUCT_H
#define ADDR_STRUCT_H

#include "hash.h"
#include <sys/socket.h>
#include "ip_util.h"

/**
 * Blacklist bucket: key type
 */
template<int mask>
struct addr: public sockaddr_storage
{
  addr()
  {
    ss_family = AF_INET;
  }
  addr(const addr<mask>& addr_)
  {
    memcpy(this,&addr_,SA_len(&addr_));
  }
  addr(const sockaddr_storage* p_addr)
  {
    memcpy((sockaddr_storage*)this,p_addr,SA_len(p_addr));
  }

  unsigned int hash()
  {
    return hashlittle((sockaddr_storage*)this, SA_len(this), 0) & mask;
  }
};

template<int mask>
struct addr_less
{
  bool operator() (const addr<mask>& l, const addr<mask>& r) const
  {
    if(l.ss_family != r.ss_family)
        return l.ss_family < r.ss_family;

    return memcmp(&l,&r,SA_len(&l));
  }
};

#endif/*ADDR_STRUCT_H*/

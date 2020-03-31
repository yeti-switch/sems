#ifndef ADDR_STRUCT_H
#define ADDR_STRUCT_H

#include "hash.h"
#include <sys/socket.h>
#include "ip_util.h"
#include "transport.h"

/**
 * Blacklist bucket: key type
 */

template<typename addr>
struct tr_addr : public addr
{
    unsigned char transport;
    tr_addr() {
        addr::ss_family = AF_INET;
        transport = trsp_socket::udp_ipv4;
    }
    tr_addr(const sockaddr_storage* p_addr)
    {
        memcpy((sockaddr_storage*)this,p_addr,size());
    }

    int size() const
    {
        return SA_len((sockaddr_storage*)this) + sizeof(transport);
    }
};

typedef tr_addr<sockaddr_in> tr_addr4;
typedef tr_addr<sockaddr_in6> tr_addr6;
#define SS2TR_ADDR(addr, tr) (addr)->ss_family == AF_INET ? \
                              (((tr_addr4*)(addr))->transport = (tr)) : \
                              (((tr_addr6*)(addr))->transport = (tr))
#define SS2TR_ADDR_SIZE(addr) addr->ss_family == AF_INET ? \
                              (((tr_addr4*)addr)->size()) : \
                              (((tr_addr6*)addr)->size())
template<>
struct tr_addr<sockaddr_storage> : public sockaddr_storage
{
    tr_addr() {
        ss_family = AF_INET;
        ((tr_addr4*)this)->transport = trsp_socket::udp_ipv4;
    }
    tr_addr(const tr_addr<sockaddr_storage>* p_addr)
    {
        memcpy((sockaddr_storage*)this,p_addr,SS2TR_ADDR_SIZE(p_addr));
    }

    tr_addr(const sockaddr_storage* p_addr)
    {
        memcpy((sockaddr_storage*)this,p_addr,SS2TR_ADDR_SIZE(p_addr));
    }

    int size() const{
        return SS2TR_ADDR_SIZE(this);
    }

    int transport() const
    {
        return ss_family == AF_INET ? (((tr_addr4*)this)->transport) : ((tr_addr6*)this)->transport;
    }
};


template<int mask>
struct addr : public tr_addr<sockaddr_storage>
{
  addr(){}
  addr(const addr<mask>& addr_)
  : tr_addr<sockaddr_storage>(addr_){}
  addr(const sockaddr_storage* p_addr)
  : tr_addr<sockaddr_storage>(p_addr){}

  unsigned int hash()
  {
    return hashlittle((tr_addr<sockaddr_storage>*)this, size(), 0) & mask;
  }
};

template<int mask>
struct addr_less
{
  bool operator() (const addr<mask>& l, const addr<mask>& r) const
  {
    if(l.ss_family != r.ss_family)
        return l.ss_family < r.ss_family;

    return memcmp(&l,&r,l.size());
  }
};

#endif/*ADDR_STRUCT_H*/

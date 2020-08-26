#pragma once

#include "hash.h"
#include <sys/socket.h>
#include "ip_util.h"/*
#include "transport.h"*/

/**
 * Blacklist bucket: key type
 */

using tr_transport_type = unsigned char;

#define SA_transport(addr) (*(reinterpret_cast<tr_transport_type *>(addr) + SA_len(addr)))
#define SA_transport_const(addr) (*(reinterpret_cast<const tr_transport_type *>(addr) + SA_len(addr)))
#define SA_transport_len(addr) (SA_len(addr) + sizeof(tr_transport_type))

struct sa_storage_transport: public sockaddr_storage
{
    sa_storage_transport(const sockaddr_storage *p_addr)
    {
        memcpy(this,p_addr,SA_transport_len(p_addr));
    }

    sa_storage_transport(const sa_storage_transport &other)
    {
        memcpy(this,&other,other.size());
    }

    int size() const
    {
        return SA_transport_len(this);
    }

    int transport() const
    {
        return SA_transport_const(this);
    }
};

template<int mask>
struct sa_storage_transport_key : public sa_storage_transport
{
    sa_storage_transport_key() = delete;

    sa_storage_transport_key(const sa_storage_transport_key<mask>& addr)
      : sa_storage_transport(addr)
    {}

    sa_storage_transport_key(const sockaddr_storage* addr)
      : sa_storage_transport(addr)
    {}

    static unsigned long hash(const sockaddr_storage* addr) {
        return hashlittle(addr, SA_transport_len(addr), 0) & mask;
    }

    unsigned long hash() const
    {
        return hash(this);
    }

    struct less
    {
        bool operator() (const sa_storage_transport_key<mask>& l,
                         const sa_storage_transport_key<mask>& r) const
        {
            if(l.ss_family != r.ss_family)
                return l.ss_family < r.ss_family;
            return memcmp(&l,&r,l.size());
        }
    };
};

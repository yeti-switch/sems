#pragma once

#include "defs.h"

class invalid_ptrs_t
{
    void** last;
    void* ptrs[EPOLL_MAX_EVENTS];
  public:
    invalid_ptrs_t(): last(ptrs) {}
    void add(void *ptr) { *last = ptr; last++; }
    void clear() { last = ptrs; }
    bool contain(void *ptr) const
    {
        void* const *i = ptrs;
        while(i<last){
            if(*i==ptr) return true;
            i++;
        }
        return false;
    }
};

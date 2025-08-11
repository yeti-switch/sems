#pragma once

#include <cxxabi.h>

#include "AmStatistics.h"

#ifdef OBJECTS_COUNTER

#define ObjCounter(T)     ObjectsCounter<T>
#define ObjCounterInit(T) ObjectsCounter<T>::init_object_counters()

template <typename T> struct ObjectsCounter {

    static inline AtomicCounter *objects_created;
    static inline AtomicCounter *objects_alive;

    ObjectsCounter()
    {
        objects_created->inc();
        objects_alive->inc();
    }

    ObjectsCounter(const ObjectsCounter &)
    {
        objects_created->inc();
        objects_alive->inc();
    }

    static void init_object_counters()
    {
        int    status;
        size_t length = 64;
        char   buf[length];

        auto *tname = abi::__cxa_demangle(typeid(T).name(), buf, &length, &status);

        objects_created = &stat_group(Counter, "obj", "created").addAtomicCounter().addLabel("type", tname);
        objects_alive   = &stat_group(Counter, "obj", "alive").addAtomicCounter().addLabel("type", tname);
    }

  protected:
    ~ObjectsCounter() { objects_alive->dec(); }
};

#else
#define ObjCounterInit(T)
#endif

void init_core_objects_counters();

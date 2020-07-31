#pragma once

#include <sys/time.h>
#include <unordered_map>

#include "AmEvent.h"

using TypeInfoRef = std::reference_wrapper<const std::type_info>;

struct StatsEventTypeHasher {
    std::size_t operator()(TypeInfoRef r) const
    {
        return r.get().hash_code();
    }
};

struct StatsEventTypeEqualTo {
    bool operator()(TypeInfoRef lhs, TypeInfoRef rhs) const
    {
        return lhs.get() == rhs.get();
    }
};

template <typename ValueType>
using HashByType = std::unordered_map<TypeInfoRef, ValueType, StatsEventTypeHasher, StatsEventTypeEqualTo>;

struct EventTypeStats {
    map<string,string> labels;
    string name;
    unsigned long long count;
    timeval consumed_time;

    EventTypeStats() = delete;
    EventTypeStats(const std::type_info &type_info, timeval &consumed_time, map<string,string> ext_labels);

    void update(timeval &event_consumed_time);
    void iterate_count(StatCounter::iterate_func_type f);
    void iterate_time(StatCounter::iterate_func_type f);
};

class EventStats
  : public HashByType<EventTypeStats>
{
    map<string,string> labels;
  public:
    void update(AmEvent *event, timeval &consumed_time);
    void iterate_count(StatCounter::iterate_func_type f);
    void iterate_time(StatCounter::iterate_func_type f);

    void addLabel(const string& name, const string& value);
};

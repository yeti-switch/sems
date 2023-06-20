#include "EventStats.h"
#include "AmUtils.h"

EventTypeStats::EventTypeStats(const std::type_info &type_info, timeval &consumed_time, map<string,string> ext_labels)
  : labels(ext_labels),
    name(type_info.name()),
    count(1),
    consumed_time(consumed_time)
{
    labels.emplace("type", name);
}

void EventTypeStats::update(timeval &event_consumed_time) 
{
    count++;
    timeradd(&consumed_time, &event_consumed_time, &consumed_time);
}

void EventTypeStats::iterate_count(StatCounterInterface::iterate_func_type f)
{
    f(count,/*0,*/labels);
}

void EventTypeStats::iterate_time(StatCounterInterface::iterate_func_type f)
{
    f(consumed_time.tv_sec*1000 + consumed_time.tv_usec/1000, /*0,*/ labels);
}


void EventStats::update(AmEvent *event, timeval &consumed_time)
{
    try {
        auto &tinfo = typeid(*event);

        /*DBG("EventStats::update(%s,%s)",
            tinfo.name(), timeval2str_usec(consumed_time).data());*/

        auto it = find(tinfo);
        if(it == end()) {
            emplace(tinfo, EventTypeStats(tinfo, consumed_time, labels));
        } else {
            it->second.update(consumed_time);
        }
    } catch(const std::bad_typeid& e) {
        ERROR("EventStats::update(%p,%s) exception: %s",
              event, timeval2str_usec(consumed_time).data(),
              e.what());
    }
}

void EventStats::iterate_count(StatCounterInterface::iterate_func_type f)
{
    for(auto &it: *this) {
        it.second.iterate_count(f);
    }
}

void EventStats::iterate_time(StatCounterInterface::iterate_func_type f)
{
    for(auto &it: *this) {
        it.second.iterate_time(f);
    }
}

void EventStats::addLabel(const string& name, const string& value)
{
    labels.emplace(name, value);
}

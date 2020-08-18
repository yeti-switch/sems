#include "AmStatistics.h"

#include <stdexcept>

StatCounter::~StatCounter()
{}

void StatCounter::addLabel(const string& name, const string& value)
{
    labels.emplace(name, value);
}

AtomicCounter::AtomicCounter()
{
    timestamp.set(wheeltimer::instance()->unix_ms_clock.get());
}

AtomicCounter& AtomicCounter::addLabel(const string& name, const string& value)
{
    labels.emplace(name, value);
    return *this;
}

void AtomicCounter::iterate(iterate_func_type callback)
{
    callback(atomic_int64::get(), timestamp.get(), getLabels());
}

unsigned long long AtomicCounter::inc(unsigned long long add)
{
    timestamp.set(wheeltimer::instance()->unix_ms_clock.get());
    return atomic_int64::inc(add);
}

unsigned long long AtomicCounter::dec(unsigned long long sub)
{
    timestamp.set(wheeltimer::instance()->unix_ms_clock.get());
    return atomic_int64::dec(sub);
}

void AtomicCounter::set(unsigned long long value)
{
    timestamp.set(wheeltimer::instance()->unix_ms_clock.get());
    return atomic_int64::set(value);
}

FunctionCounter& FunctionCounter::addLabel(const string& name, const string& value)
{
    labels.emplace(name, value);
    return *this;
}

void FunctionCounter::iterate(
    std::function<void(unsigned long long value,
                       unsigned long long timestamp,
                       const map<string, string>&)> callback)
{
    callback(func_(), 0, getLabels());
}

void FunctionGroupCounter::iterate(iterate_func_type callback)
{
    func_(callback);
}

StatCountersGroup::~StatCountersGroup()
{
    for(auto &counter : counters)
        delete counter;
}

void StatCountersGroup::iterate(
    std::function<void(unsigned long long value,
                       unsigned long long timestamp,
                       const map<string, string>&)> callback)
{
    AmLock l(counters_lock);

    for(auto& counter : counters) {
        counter->iterate(callback);
    }
}

AtomicCounter& StatCountersGroup::addAtomicCounter()
{
    AmLock l(counters_lock);

    auto counter = new AtomicCounter();
    counters.emplace_back(counter);
    return *counter;
}

FunctionCounter& StatCountersGroup::addFunctionCounter(FunctionCounter::CallbackFunction func)
{
    AmLock l(counters_lock);

    auto counter = new FunctionCounter(func);
    counters.emplace_back(counter);
    return *counter;
}

FunctionGroupCounter& StatCountersGroup::addFunctionGroupCounter(FunctionGroupCounter::CallbackFunction func)
{
    AmLock l(counters_lock);

    auto counter = new FunctionGroupCounter(func);
    counters.emplace_back(counter);
    return *counter;
}

AmStatistics::AmStatistics()
{}

AmStatistics::~AmStatistics()
{}

string AmStatistics::get_concatenated_name(const string& naming_group, const string& name)
{
    return naming_group + "_" + name;
}

void AmStatistics::addLabel(const string& name, const string& value)
{
    labels.emplace(name, value);
}

const map<string, string> &AmStatistics::getLabels() const
{
    return labels;

}

void AmStatistics::iterate(iterate_callback_type callback)
{
    AmLock lock(groups_mutex);
    for(auto &it : counters_groups) {
        callback(it.first, it.second);
    }
}

StatCountersGroup &AmStatistics::group(StatCountersGroup::Type type, const string& naming_group, const string& name)
{
    return group(type, get_concatenated_name(naming_group,name));
}

StatCountersGroup &AmStatistics::group(StatCountersGroup::Type type, const string& name)
{
    AmLock lock(groups_mutex);

    auto it = counters_groups.emplace(name, type);
    auto &group = it.first->second;

    if(it.second == false && group.type() != type) {
        ERROR("attempt to add counter '%s' with type '%s' to existing counters group with another type '%s'",
            name.data(),
            StatCountersGroup::type2str(type),
            StatCountersGroup::type2str(group.type()));
        throw std::logic_error("attempt to redefine existent StatCountersGroup");
    }

    return group;
}

const char *StatCountersGroup::type2str(Type type)
{
    switch(type) {
        case Counter: return "counter";
        case Gauge: return "gauge";
        case Histogram: return "histogram";
        case Summary: return "summary";
        default: break;
    }
    return "unknown";
}

StatCountersGroup::Type StatCountersGroup::str2type(const char * type)
{
    if(strcmp(type, "counter") == 0) return Counter;
    if(strcmp(type, "gauge") == 0) return Gauge;
    if(strcmp(type, "histogram") == 0) return Histogram;
    if(strcmp(type, "summary") == 0) return Summary;
    return Unknown;
}

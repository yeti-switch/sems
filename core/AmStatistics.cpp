#include "AmStatistics.h"

#include <stdexcept>

StatCounterInterface::~StatCounterInterface()
{}

AtomicCounter::AtomicCounter()
{
    //timestamp.set(wheeltimer::instance()->unix_ms_clock.get());
}

AtomicCounter& AtomicCounter::addLabel(const string& name, const string& value)
{
    addLabelInternal(name, value);
    return *this;
}

void AtomicCounter::iterate(iterate_func_type callback)
{
    callback(atomic_int64::get(), /*timestamp.get(),*/ getLabels());
}

/*unsigned long long AtomicCounter::inc(unsigned long long add)
{
    //timestamp.set(wheeltimer::instance()->unix_ms_clock.get());
    return atomic_int64::inc(add);
}

unsigned long long AtomicCounter::dec(unsigned long long sub)
{
    //timestamp.set(wheeltimer::instance()->unix_ms_clock.get());
    return atomic_int64::dec(sub);
}

void AtomicCounter::set(unsigned long long value)
{
    //timestamp.set(wheeltimer::instance()->unix_ms_clock.get());
    return atomic_int64::set(value);
}*/

FunctionCounter& FunctionCounter::addLabel(const string& name, const string& value)
{
    addLabelInternal(name, value);
    return *this;
}

void FunctionCounter::iterate(
    std::function<void(unsigned long long value,
                       /*unsigned long long timestamp,*/
                       const map<string, string>&)> callback)
{
    callback(func_(), /*0,*/ getLabels());
}

void FunctionGroupCounter::iterate(iterate_func_type callback)
{
    func_(callback);
}

const char *StatCountersGroupsInterface::type2str(Type type)
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

StatCountersGroupsInterface::Type StatCountersGroupsInterface::str2type(const char * type)
{
    if(strcmp(type, "counter") == 0) return Counter;
    if(strcmp(type, "gauge") == 0) return Gauge;
    if(strcmp(type, "histogram") == 0) return Histogram;
    if(strcmp(type, "summary") == 0) return Summary;
    return Unknown;
}

StatCountersSingleGroup::~StatCountersSingleGroup()
{
    for(auto &counter : counters)
        delete counter;
}

AtomicCounter& StatCountersSingleGroup::addAtomicCounter()
{
    AmLock l(counters_lock);

    auto counter = new AtomicCounter();
    counters.emplace_back(counter);
    return *counter;
}

FunctionCounter& StatCountersSingleGroup::addFunctionCounter(FunctionCounter::CallbackFunction func)
{
    AmLock l(counters_lock);

    auto counter = new FunctionCounter(func);
    counters.emplace_back(counter);
    return *counter;
}

FunctionGroupCounter& StatCountersSingleGroup::addFunctionGroupCounter(FunctionGroupCounter::CallbackFunction func)
{
    AmLock l(counters_lock);

    auto counter = new FunctionGroupCounter(func);
    counters.emplace_back(counter);
    return *counter;
}

void StatCountersSingleGroup::operator ()(const string &name, iterate_groups_callback_type callback)
{
    callback(name, *this);
}

void StatCountersSingleGroup::iterate_counters(iterate_counters_callback_type callback)
{
    AmLock l(counters_lock);

    for(auto& counter : counters) {
        counter->iterate(callback);
    }
}

AmStatistics::AmStatistics()
{}

AmStatistics::~AmStatistics()
{}

string AmStatistics::get_concatenated_name(const string& naming_group, const string& name)
{
    return naming_group + "_" + name;
}

AmStatistics& AmStatistics::addLabel(const string& name, const string& value)
{
    addLabelInternal(name, value);
    return *this;
}

void AmStatistics::iterate_groups(StatsCountersGroupsContainerInterface::iterate_groups_callback_type callback)
{
    AmLock lock(groups_mutex);
    for(auto &it : counters_groups_containers) {
        (*it.second.groups_container)(it.first, callback);
    }
}

StatCountersSingleGroup &AmStatistics::group(StatCountersSingleGroup::Type type, const string& naming_group, const string& name)
{
    return group(type, get_concatenated_name(naming_group,name));
}

StatCountersSingleGroup &AmStatistics::group(StatCountersSingleGroup::Type type, const string& name)
{
    AmLock lock(groups_mutex);

    auto it = counters_groups_containers.try_emplace(name, new StatCountersSingleGroup(type), true);
    auto &existent_group = *dynamic_cast<StatCountersSingleGroup *>(it.first->second.groups_container);

    if(it.second == false && existent_group.getType() != type) {
        ERROR("attempt to add counter '%s' with type '%s' to existing counters group with another type '%s'",
            name.data(),
            StatCountersGroupsInterface::type2str(type),
            StatCountersGroupsInterface::type2str(existent_group.getType()));
        throw std::logic_error("attempt to redefine existent StatCountersSingleGroup");
    }

    return existent_group;
}

void AmStatistics::add_groups_container(const string& name, StatsCountersGroupsContainerInterface *container,
                                        bool is_managed_by_am_statistics)
{
    auto it = counters_groups_containers.try_emplace(name, container, is_managed_by_am_statistics);
    if(it.second == false) {
        ERROR("attempt to add groups container  %p by existing name: %s",
            container, name.data());
        throw std::logic_error("attempt to redefine existent StatCountersGroup");
    }
}

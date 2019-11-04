#include "AmStatistics.h"

AmStatistics::AmStatistics()
{
}

AmStatistics::~AmStatistics()
{
    for(auto counter : counters) {
        delete counter;
    }
}

void AmStatistics::AddLabel(const string& name, const string& value)
{
    labels.emplace(name, value);
}

const vector<StatCounter*> &AmStatistics::GetCounters()
{
    return counters;
}

const map<string, string> &AmStatistics::GetLabels() const
{
    return labels;
}

AtomicCounter& AmStatistics::NewAtomicCounter(StatCounter::CounterType type, const string& group, const string& name)
{
    AmLock lock(counterMutex);
    AtomicCounter *counter = new AtomicCounter(type, group, name);
    counters.push_back(counter);
    return *counter;
}

FunctionCounter& AmStatistics::NewFunctionCounter(FunctionCounter::FuncCounter func, StatCounter::CounterType type, const string& group, const string& name)
{
    AmLock lock(counterMutex);
    FunctionCounter *counter = new FunctionCounter(type, group, name, func);
    counters.push_back(counter);
    return *counter;
}

AtomicCounter::AtomicCounter(StatCounter::CounterType type, const std::__cxx11::string& group, const std::__cxx11::string& name)
: StatCounter(type, group, name) {
    timestamp.set(wheeltimer::instance()->unix_ms_clock.get());
}


unsigned long long AtomicCounter::inc()
{
    timestamp.set(wheeltimer::instance()->unix_ms_clock.get());
    return atomic_int64::inc();
}


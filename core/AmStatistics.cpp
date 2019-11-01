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


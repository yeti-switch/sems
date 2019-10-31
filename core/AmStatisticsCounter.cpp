#include "AmStatisticsCounter.h"

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
    labels.insert(std::make_pair(name, value));
}

vector<StatCounter*> AmStatistics::GetCounters()
{
    AmLock lock(counterMutex);
    return counters;
}

map<string, string> AmStatistics::GetLabels()
{
    return labels;
}

map<string, string> AmStatistics::GetLabels(const map<string, string>& c_labels)
{
    map<string, string> ret = labels;
    for(auto label : c_labels) {
        ret[label.first] = label.second;
    }
    return ret;
}

AtomicCounter* AmStatistics::NewAtomicCounter(StatCounter::CounterType type, const string& group, const string& name)
{
    AmLock lock(counterMutex);
    AtomicCounter *counter = new AtomicCounter(type, group, name);
    counters.push_back(counter);
    return counter;
}

FunctionCounter* AmStatistics::NewFunctionCounter(FunctionCounter::FuncCounter func, StatCounter::CounterType type, const string& group, const string& name)
{
    AmLock lock(counterMutex);
    FunctionCounter *counter = new FunctionCounter(type, group, name, func);
    counters.push_back(counter);
    return counter;
}


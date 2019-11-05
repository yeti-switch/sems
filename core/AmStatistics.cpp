#include "AmStatistics.h"

NullCounter null_counter;

AmStatistics::AmStatistics()
{
}

AmStatistics::~AmStatistics()
{
    for(auto counter : counters) {
        delete counter.second;
    }
}

void AmStatistics::AddLabel(const string& name, const string& value)
{
    labels.emplace(name, value);
}

void AmStatistics::iterate(std::function<void(MultiplyCounter*)> callback)
{
    AmLock lock(counterMutex);
    for(auto counter : counters) {
        callback(counter.second);
    }
}

const map<string, string> &AmStatistics::GetLabels() const
{
    return labels;
}

AtomicCounter& AmStatistics::NewAtomicCounter(StatCounter::CounterType type, const string& group, const string& name)
{
    AmLock lock(counterMutex);
    AtomicCounter *counter = new AtomicCounter(type, group, name);
    MultiplyCounter* mcounter;
    auto counter_it = counters.find(counter->name());
    if(counter_it != counters.end()) {
        mcounter = counter_it->second;
        if(mcounter->type() != type) {
            ERROR("new counter have type is not equal to existing counter %s: new - %s, old - %s"
                    , counter->name().c_str(), counter->type_str(), mcounter->type_str());
            delete counter;
            return null_counter;
        }
    } else {
        counters.insert(std::make_pair(counter->name(), mcounter = new MultiplyCounter(type, group, name)));
    }
    mcounter->addCounter(counter);
    return *counter;
}

FunctionCounter& AmStatistics::NewFunctionCounter(FunctionCounter::FuncCounter func, StatCounter::CounterType type, const string& group, const string& name)
{
    AmLock lock(counterMutex);
    FunctionCounter *counter = new FunctionCounter(type, group, name, func);
    MultiplyCounter* mcounter;
    auto counter_it = counters.find(counter->name());
    if(counter_it != counters.end()) {
        mcounter = counter_it->second;
        if(mcounter->type() != type) {
            ERROR("new counter have type is not equal to existing counter %s: new - %s, old - %s"
                    , counter->name().c_str(), counter->type_str(), mcounter->type_str());
            delete counter;
            return null_counter;
        }
    } else {
        counters.insert(std::make_pair(counter->name(), mcounter = new MultiplyCounter(type, group, name)));
    }
    mcounter->addCounter(counter);
    return *counter;
}

void AmStatistics::SetHelp(const std::__cxx11::string& group, const std::__cxx11::string& name, const string& help)
{
    AmLock lock(counterMutex);
    for(auto counter : counters) {
        if(counter.second->name() == group + name) {
            counter.second->setHelp(help);
        }
    }
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

void FunctionCounter::iterate(std::function<void(unsigned long long value, unsigned long long timestamp, const map<string, string>&)> callback)
{
    callback(func_(), wheeltimer::instance()->unix_ms_clock.get(), getLabels());
}

NullCounter::NullCounter()
: AtomicCounter(StatCounter::Counter, "", "")
, FunctionCounter(StatCounter::Counter, "", "", []()->unsigned long long{ return 0; }){}

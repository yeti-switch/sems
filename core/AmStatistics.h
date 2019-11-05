#pragma once

#include "singleton.h"
#include "atomic_types.h"
#include "sip/wheeltimer.h"

#include <vector>
#include <map>
#include <functional>
using std::vector;
using std::map;

class StatCounter
{
  public:
    enum CounterType
    {
        Counter,
        Gauge,
        Histogram,
        Summary
    };

  private:
    CounterType type_;
    string name_;
    string group_;
    string concatenated_name_;
    map<string, string> labels;

  public:
    StatCounter(CounterType type, const string& group, const string& name)
     : type_(type),
       name_(name),
       group_(group)
    {
        concatenated_name_ = group_ + "_" + name_;
    }
    virtual ~StatCounter() {}

    CounterType type()
    {
        return type_;
    }

    void addLabel(const string& name, const string& value)
    {
        labels.insert(std::make_pair(name, value));
    }

    const map<string, string>& getLabels()
    {
        return labels;
    }

    const char *type_str()
    {
        switch(type_) {
        case Counter: return "counter";
        case Gauge: return "gauge";
        case Histogram: return "histogram";
        case Summary: return "summary";
        }
        return "unknown";
    }

    const string &name()
    {
        return concatenated_name_;
    }

    virtual void iterate(std::function<void(unsigned long long value, unsigned long long timestamp, const map<string, string>&)>) = 0;
};

class AtomicCounter : public atomic_int64, public StatCounter
{
    atomic_int64 timestamp;
public:
    AtomicCounter(CounterType type, const string& group, const string& name);

    virtual void iterate(std::function<void(unsigned long long value, unsigned long long timestamp, const map<string, string>&)> callback)
    {
        callback(atomic_int64::get(), timestamp.get(), getLabels());
    }

    unsigned long long inc();
};

class FunctionCounter : public StatCounter
{
public:
    typedef unsigned long long (*FuncCounter)();
    FunctionCounter(CounterType type, const string& group, const string& name, FuncCounter func)
    : StatCounter(type, group, name), func_(func){}

    virtual void iterate(std::function<void(unsigned long long value, unsigned long long timestamp, const map<string, string>&)> callback);
private:
    FuncCounter func_;
};

class MultiplyCounter : public StatCounter
{
    vector<StatCounter*> counters;
    string help_;
public:
    MultiplyCounter(CounterType type, const string& group, const string& name)
    : StatCounter(type, group, name){}
    ~MultiplyCounter()
    {
        for(auto counter : counters) delete counter;
    }

    virtual void iterate(std::function<void(unsigned long long value, unsigned long long timestamp, const map<string, string>&)> callback)
    {
        for(auto& counter : counters) {
            counter->iterate(callback);
        }
    };

    void addCounter(StatCounter* counter)
    {
        counters.push_back(counter);
    }

    void setHelp(const string& help)
    {
        help_ = help;
    }

    const string &getHelp()
    {
        return help_;
    }

};

class NullCounter : public AtomicCounter, public FunctionCounter
{
public:
    NullCounter();
};

class AmStatistics
{
protected:
    AmStatistics();
    ~AmStatistics();
    void dispose() {}
public:
    void AddLabel(const string& name, const string& value);
    const map<string, string> &GetLabels() const;

    void iterate(std::function<void(MultiplyCounter*)> callback);

    AtomicCounter& NewAtomicCounter(StatCounter::CounterType type, const string& group, const string& name);
    FunctionCounter& NewFunctionCounter(FunctionCounter::FuncCounter func, StatCounter::CounterType type, const string& group, const string& name);
    void SetHelp(const string& group, const string& name, const string& help);
private:
    AmMutex counterMutex;
    map<string, MultiplyCounter*> counters;
    map<string, string> labels;
};

typedef singleton<AmStatistics> statistics;

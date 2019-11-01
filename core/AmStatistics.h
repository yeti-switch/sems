#pragma once

#include "singleton.h"
#include "atomic_types.h"

#include <vector>
#include <map>
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
    string help_;
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

    void setHelp(const string& help)
    {
        help_ = help;
    }

    const string &getHelp()
    {
        return help_;
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

    virtual void get(unsigned long long* counter) = 0;
};

class AtomicCounter : public atomic_int64, public StatCounter
{
public:
    AtomicCounter(CounterType type, const string& group, const string& name)
    : StatCounter(type, group, name){}

    virtual void get(unsigned long long* counter)
    {
        *counter = atomic_int64::get();
    }
};

class FunctionCounter : public StatCounter
{
public:
    typedef unsigned long long (*FuncCounter)();
    FunctionCounter(CounterType type, const string& group, const string& name, FuncCounter func)
    : StatCounter(type, group, name), func_(func){}

    virtual void get(unsigned long long* counter)
    {
        *counter = func_();
    }
private:
    FuncCounter func_;
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

    const vector<StatCounter*> &GetCounters();
    AmMutex &GetCountersMutex() { return counterMutex; }

    AtomicCounter& NewAtomicCounter(StatCounter::CounterType type, const string& group, const string& name);
    FunctionCounter& NewFunctionCounter(FunctionCounter::FuncCounter func, StatCounter::CounterType type, const string& group, const string& name);
private:
    AmMutex counterMutex;
    vector<StatCounter*> counters;
    map<string, string> labels;
};

typedef singleton<AmStatistics> statistics;

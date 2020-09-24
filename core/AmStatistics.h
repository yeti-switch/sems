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
  protected:
    map<string, string> labels;

  public:
    using iterate_func_type = std::function<
        void (unsigned long long value,
              unsigned long long timestamp,
              const map<string, string>&) >;

    StatCounter() = default;
    StatCounter(StatCounter const &) = delete;
    StatCounter(StatCounter const &&) = delete;
    virtual ~StatCounter();

    void addLabel(const string& name, const string& value);
    const map<string, string>& getLabels() { return labels; }

    virtual void iterate(iterate_func_type) = 0;
};

class AtomicCounter
  : public atomic_int64,
    public StatCounter
{
    atomic_int64 timestamp;
  public:
    AtomicCounter();
    AtomicCounter(AtomicCounter const &) = delete;
    AtomicCounter(AtomicCounter const &&) = delete;
    ~AtomicCounter() override {}

    AtomicCounter &addLabel(const string& name, const string& value);
    void iterate(iterate_func_type callback) override;
    unsigned long long inc(unsigned long long add=1);
    unsigned long long dec(unsigned long long sub=1);
    void set(unsigned long long value);
};

class FunctionCounter
  : public StatCounter
{
  public:
    typedef unsigned long long (*CallbackFunction)();

    FunctionCounter(CallbackFunction func)
      : func_(func)
    {}
    FunctionCounter(FunctionCounter const &) = delete;
    FunctionCounter(FunctionCounter const &&) = delete;
    ~FunctionCounter() override {}

    FunctionCounter &addLabel(const string& name, const string& value);
    void iterate(iterate_func_type callback) override;

  private:
    CallbackFunction func_;
};

class FunctionGroupCounter
  : public StatCounter
{
  public:
    typedef void (*CallbackFunction)(iterate_func_type callback);

    FunctionGroupCounter(CallbackFunction func)
      : func_(func)
    {}
    FunctionGroupCounter(FunctionGroupCounter const &) = delete;
    FunctionGroupCounter(FunctionGroupCounter const &&) = delete;
    ~FunctionGroupCounter() override {}

    void iterate(iterate_func_type callback) override;

  private:
    CallbackFunction func_;
};

//represents set of counters with the same name
class StatCountersGroup final
  : public StatCounter
{
  public:
    enum Type
    {
        Counter,
        Gauge,
        Histogram,
        Summary,
        Unknown
    };

  private:
    vector<StatCounter *> counters;
    AmMutex counters_lock;

    Type type_;
    string help_;

public:
    StatCountersGroup(Type type)
      : type_(type)
    { }
    StatCountersGroup(StatCountersGroup const &) = delete;
    StatCountersGroup(StatCountersGroup const &&) = delete;

    ~StatCountersGroup();

    void iterate(
        std::function<void(unsigned long long value,
                           unsigned long long timestamp,
                           const map<string, string>&)> callback);

    AtomicCounter& addAtomicCounter();
    FunctionCounter& addFunctionCounter(FunctionCounter::CallbackFunction func);
    FunctionGroupCounter& addFunctionGroupCounter(FunctionGroupCounter::CallbackFunction func);

    static const char *type2str(Type type);
    static Type str2type(const char * type);

    StatCountersGroup &setHelp(const string& help) { help_ = help;  return *this; }
    const string &help() { return help_; }

    Type type() { return type_; }
};

class AmStatistics
{
  private:
    AmMutex groups_mutex;
    map<string, StatCountersGroup> counters_groups;
    map<string, string> labels;

  protected:
    AmStatistics();
    ~AmStatistics();
    void dispose() {}

    string get_concatenated_name(const string& naming_group, const string& name);

  public:
    void addLabel(const string& name, const string& value);
    const map<string, string> &getLabels() const;

    using iterate_callback_type = std::function<void(const std::string &,StatCountersGroup &)>;
    void iterate(iterate_callback_type callback);

    //get or create group
    StatCountersGroup &group(StatCountersGroup::Type type, const string& naming_group, const string& name);
    StatCountersGroup &group(StatCountersGroup::Type type, const string& name);
};

typedef singleton<AmStatistics> statistics;

#define stat_group(type, grouping_name, name) statistics::instance()->group(StatCountersGroup::type, grouping_name, name)

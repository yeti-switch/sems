#pragma once

#include "singleton.h"
#include "atomic_types.h"
#include "sip/wheeltimer.h"

#include <vector>
#include <map>
#include <memory>
#include <functional>

using std::vector;
using std::map;
using std::shared_ptr;

template <class Parent>
class StatLabelsContainer {
  protected:
    map<string, string> labels;
    void addLabelInternal(const string& name, const string& value)
    {
        labels.emplace(name, value);
    }
  public:
    const map<string, string>& getLabels() { return labels; }
    virtual Parent &addLabel(const string& name, const string& value) = 0;
};

class StatCounterInterface
{
  public:
    using iterate_func_type = std::function<
        void (unsigned long long value,
              unsigned long long timestamp,
              const map<string, string>&) >;

    StatCounterInterface() = default;
    StatCounterInterface(StatCounterInterface const &) = delete;
    StatCounterInterface(StatCounterInterface const &&) = delete;
    virtual ~StatCounterInterface();

    virtual void iterate(iterate_func_type) = 0;
};

class AtomicCounter
  : public atomic_int64,
    public StatCounterInterface,
    public StatLabelsContainer<AtomicCounter>
{
    atomic_int64 timestamp;
  public:
    AtomicCounter();
    AtomicCounter(AtomicCounter const &) = delete;
    AtomicCounter(AtomicCounter const &&) = delete;
    ~AtomicCounter() override {}

    AtomicCounter &addLabel(const string& name, const string& value) override;
    void iterate(iterate_func_type callback) override;
    unsigned long long inc(unsigned long long add=1);
    unsigned long long dec(unsigned long long sub=1);
    void set(unsigned long long value);
};

class FunctionCounter
  : public StatCounterInterface,
    public StatLabelsContainer<FunctionCounter>
{
  public:
    typedef unsigned long long (*CallbackFunction)();

    FunctionCounter(CallbackFunction func)
      : func_(func)
    {}
    FunctionCounter(FunctionCounter const &) = delete;
    FunctionCounter(FunctionCounter const &&) = delete;
    ~FunctionCounter() override {}

    FunctionCounter &addLabel(const string& name, const string& value) override;
    void iterate(iterate_func_type callback) override;

  private:
    CallbackFunction func_;
};

class FunctionGroupCounter
  : public StatCounterInterface
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

class StatCountersGroupsInterface
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

    using iterate_counters_callback_type =
        std::function<void (unsigned long long value,
                            unsigned long long timestamp,
                            const map<string, string>&)>;
  private:
    Type type_;
    string help_;

  public:
    StatCountersGroupsInterface(Type type)
      : type_(type)
    {}
    StatCountersGroupsInterface(StatCountersGroupsInterface const &) = delete;
    StatCountersGroupsInterface(StatCountersGroupsInterface const &&) = delete;

    virtual void iterate_counters(iterate_counters_callback_type callback) = 0;

    static const char *type2str(Type type);
    static Type str2type(const char * type);

    StatCountersGroupsInterface &setHelp(const string& help) { help_ = help;  return *this; }
    const string &getHelp() { return help_; }

    void setType(StatCountersGroupsInterface::Type type) { type_ = type; }
    StatCountersGroupsInterface::Type getType() { return type_; }
};

class StatsCountersGroupsContainerInterface {
  public:
    StatsCountersGroupsContainerInterface() = default;
    virtual ~StatsCountersGroupsContainerInterface(){}
    using iterate_groups_callback_type =
        std::function<void(const std::string &name,
                           StatCountersGroupsInterface &group)>;
    virtual void operator ()(const string &name, iterate_groups_callback_type callback) = 0;
};

//represents set of counters with the same name
class StatCountersSingleGroup final
  : public StatCountersGroupsInterface,
    public StatsCountersGroupsContainerInterface
{
    vector<StatCounterInterface *> counters;
    AmMutex counters_lock;

  public:
    StatCountersSingleGroup(Type type)
      : StatCountersGroupsInterface(type)
    { }
    StatCountersSingleGroup(StatCountersSingleGroup const &) = delete;
    StatCountersSingleGroup(StatCountersSingleGroup const &&) = delete;

    ~StatCountersSingleGroup();

    AtomicCounter& addAtomicCounter();
    FunctionCounter& addFunctionCounter(FunctionCounter::CallbackFunction func);
    FunctionGroupCounter& addFunctionGroupCounter(FunctionGroupCounter::CallbackFunction func);

    void operator ()(const string &name, iterate_groups_callback_type callback) override;
    void iterate_counters(iterate_counters_callback_type callback) override;
};

class AmStatistics
  : public StatLabelsContainer<AmStatistics>
{
  private:
    AmMutex groups_mutex;

    struct GroupContainerEntry {
        StatsCountersGroupsContainerInterface *groups_container;
        bool managed_by_am_statistics;
        GroupContainerEntry(
            StatsCountersGroupsContainerInterface *groups_container,
            bool managed_by_am_statistics)
          : groups_container(groups_container),
            managed_by_am_statistics(managed_by_am_statistics)
        {}
    };
    map<string, GroupContainerEntry> counters_groups_containers;

  protected:
    AmStatistics();
    virtual ~AmStatistics();
    void dispose() {
        for(auto& it : counters_groups_containers) {
            if(it.second.managed_by_am_statistics) delete it.second.groups_container;
        }
    }

    string get_concatenated_name(const string& naming_group, const string& name);

  public:
    AmStatistics& addLabel(const string& name, const string& value) override;

    void iterate_groups(StatsCountersGroupsContainerInterface::iterate_groups_callback_type callback);

    //get or create group
    StatCountersSingleGroup &group(StatCountersSingleGroup::Type type, const string& naming_group, const string& name);
    StatCountersSingleGroup &group(StatCountersSingleGroup::Type type, const string& name);

    void add_groups_container(const string& name, StatsCountersGroupsContainerInterface *container,
                              bool is_managed_by_am_statistics);
};

typedef singleton<AmStatistics> statistics;

#define stat_group(type, grouping_name, name) statistics::instance()->group(StatCountersSingleGroup::type, grouping_name, name)

#pragma once

#include <string>
#include <map>
#include "log.h"

#include <chrono>
#include <ratio>

using std::map;
using std::string;
using std::chrono::milliseconds;
using std::chrono::system_clock;

class RegShaper {
  public:
    typedef system_clock::time_point timep;
    typedef string                   ThrottlingHashKey;

  private:
    typedef timep                                       ThrottlingHashValue;
    typedef map<ThrottlingHashKey, ThrottlingHashValue> ThrottlingHash;
    typedef map<ThrottlingHashKey, milliseconds>        ThrottlingIntervalsHash;

    bool                    enabled;
    milliseconds            min_interval;
    ThrottlingHash          throttling_hash;
    ThrottlingIntervalsHash throttling_intervals_hash;
    ThrottlingHashValue     global_last_req_time;
    milliseconds            postponed_regs_timer_interval;

    milliseconds diff(const timep &tp1, const timep &tp2);
    void         recalc_postponed_regs_timer_interval(int key_min_interval = 0);

  public:
    RegShaper()
        : enabled(false)
        , min_interval(milliseconds::zero())
        , postponed_regs_timer_interval(milliseconds::zero())
    {
    }

    /**
     * @brief check if we have to postpone operation
     * @param[in] key key for throttling bucket
     * @param[out] next_attempt_time scheduled time for next attempt for the operation
     * @return true if have to be postponed
     */
    bool check_rate_limit(const ThrottlingHashKey &key, timep &next_attempt_time);
    /**
     * @brief check if we have to postpone operation (with external now timepoint)
     * @param[in] key key for throttling bucket
     * @param[in] now timepoint
     * @param[out] next_attempt_time scheduled time for next attempt for the operation
     * @return true if have to be postponed
     */
    bool check_rate_limit(const ThrottlingHashKey &key, const timep &now, timep &next_attempt_time);

    void set_min_interval(int msec)
    {
        min_interval = milliseconds(msec);
        enabled      = true;
        recalc_postponed_regs_timer_interval();
    }

    int get_min_interval() { return min_interval.count(); }

    void set_key_min_interval(const string &key, int msec)
    {
        auto interval = milliseconds(msec);
        if (min_interval != milliseconds::zero() && min_interval > interval) {
            WARN("global min interval(%ld) is greater than min interval(%ld) for key %s", min_interval.count(),
                 interval.count(), key.c_str());
        }
        throttling_intervals_hash.emplace(key, interval);
        enabled = true;
        recalc_postponed_regs_timer_interval(msec);
    }

    int get_postponed_regs_timer_interval() { return postponed_regs_timer_interval.count(); }
};

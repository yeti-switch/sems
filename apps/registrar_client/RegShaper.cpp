#include "RegShaper.h"
#include "log.h"

#include <ctime>
#include <limits>

inline int get_min_positive(int a, int b, int c)
{
    if (!a && !b && !c)
        return 0;
    int min_val = std::numeric_limits<int>::max();
    if (a > 0 && a < min_val)
        min_val = a;
    if (b > 0 && b < min_val)
        min_val = b;
    if (c > 0 && c < min_val)
        min_val = c;
    return min_val;
}

bool RegShaper::check_rate_limit(const string &key, timep &next_attempt_time)
{
    return check_rate_limit(key, system_clock::now(), next_attempt_time);
}

bool RegShaper::check_rate_limit(const string &key, const timep &now, timep &next_attempt_time)
{
    if (!enabled)
        return false;

    auto last_request = throttling_hash.find(key);
    if (last_request == throttling_hash.end()) {
        // last_request not found; first operation for this key

        // check min_interval
        if (min_interval == milliseconds::zero() || diff(now, global_last_req_time) >= min_interval) {
            global_last_req_time = now;
            throttling_hash[key] = global_last_req_time;
            return false;
        }

        // postpone
        global_last_req_time += min_interval;
        throttling_hash[key] = global_last_req_time;
        next_attempt_time    = global_last_req_time;
        return true;
    }

    // update global_last_req_time
    if (now > global_last_req_time)
        global_last_req_time = now;

    auto      &last_request_time       = last_request->second;
    const auto interval                = throttling_intervals_hash.find(key);
    const auto min_interval_per_domain = interval != throttling_intervals_hash.end() ? interval->second : min_interval;

    // check min_interval_per_domain
    if (diff(now, last_request_time) >= min_interval_per_domain) {
        last_request_time = now;
        return false;
    }

    // postpone
    last_request_time += min_interval_per_domain;
    next_attempt_time = last_request_time;
    return true;
}

milliseconds RegShaper::diff(const timep &tp1, const timep &tp2)
{
    return std::chrono::duration_cast<milliseconds>(tp1 - tp2);
}

void RegShaper::recalc_postponed_regs_timer_interval(int key_min_interval)
{
    int timer_interval =
        get_min_positive(min_interval.count(), key_min_interval, postponed_regs_timer_interval.count());
    postponed_regs_timer_interval = milliseconds(timer_interval);
}

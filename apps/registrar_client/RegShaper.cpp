#include "RegShaper.h"
#include "log.h"

#include <ctime>

bool RegShaper::check_rate_limit(const string &key,
                                 timep &next_attempt_time)
{
    return check_rate_limit(key,
                            system_clock::now(),
                            next_attempt_time);
}

bool RegShaper::check_rate_limit(const string &key,
                                 const  timep &now,
                                 timep &next_attempt_time)
{
    if (!enabled) return false;

    auto last_request = throttling_hash.find(key);
    if (last_request == throttling_hash.end()) {
        // last_request not found; first operation for this key

        // check min_interval
        if (diff(now, global_last_req_time) >= min_interval) {
            global_last_req_time = now;
            throttling_hash[key] = global_last_req_time;
            return false;
        }

        // postpone
        global_last_req_time += min_interval;
        throttling_hash[key] = global_last_req_time;
        next_attempt_time = global_last_req_time;
        return true;
    }

    // update global_last_req_time
    if (diff(now, global_last_req_time).count() > 0)
        global_last_req_time = now;

    auto &last_request_time = last_request->second;
    const auto interval = throttling_intervals_hash.find(key);
    const auto min_interval_per_domain =
        interval != throttling_intervals_hash.end() ? interval->second : min_interval;

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

milliseconds RegShaper::diff(const timep& tp1, const timep& tp2)
{
    return std::chrono::duration_cast<milliseconds>(tp1 - tp2);
}

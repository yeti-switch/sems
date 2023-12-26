#include "RegShaper.h"
#include "log.h"

#include <ctime>

bool RegShaper::check_rate_limit(const string &key,
                                 timep &next_attempt_time)
{
    return check_rate_limit(key,
                            std::chrono::system_clock::now(),
                            next_attempt_time);
}

bool RegShaper::check_rate_limit(const string &key,
                                 const  timep &now,
                                 timep &next_attempt_time)
{
    if (!enabled) return false;

    auto i = throttling_hash.find(key);
    if (i == throttling_hash.end()) {
        //the first operation for this key
        throttling_hash[key] = now;
        return false;
    }
    auto &last_request_time = i->second;

    const auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_request_time);
    //check global interval
    if (diff > min_interval) {
        const auto j = throttling_intervals_hash.find(key);
        if (j == throttling_intervals_hash.end() ||
            diff > j->second)
        {
            last_request_time = now;
            return false;
        }

        DBG("per-domain throttling limit reached for key: <%s>. (diff: %ld, min: %ld)",
            key.c_str(), diff.count(), j->second.count());
        last_request_time += j->second;
        next_attempt_time = last_request_time;
        return true;
    }

    DBG("global throttling limit reached for key: <%s>. (diff: %ld, min: %ld)",
        key.c_str(), diff.count(), min_interval.count());
    last_request_time += min_interval;
    next_attempt_time = last_request_time;
    return true;
}

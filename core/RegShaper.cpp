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
    if(!enabled) return false;

    ThrottlingHash::iterator i = throttling_hash.find(key);
    if(i == throttling_hash.end()) {
        //the first operation for this key
        throttling_hash[key] = now;
        return false;
    }

    //we have previous operations for this key
    timep &last_request_time = i->second;
    auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_request_time);
    if(diff > min_interval) {
        last_request_time = now;
        return false;
    }
    DBG("throttling limit reached for key: <%s>. (diff: %ld, min: %ld)",
        key.c_str(),diff.count(),min_interval.count());
    last_request_time+=min_interval;
    next_attempt_time = last_request_time;
    return true;
}

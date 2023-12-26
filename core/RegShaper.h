#pragma once

#include <string>
#include <map>
#include "log.h"

#include <chrono>
#include <ratio>

using std::string;
using std::map;

class RegShaper {
  public:
    typedef std::chrono::system_clock::time_point timep;
    typedef string ThrottlingHashKey;
  private:
    typedef timep ThrottlingHashValue;
    typedef map<ThrottlingHashKey,ThrottlingHashValue> ThrottlingHash;
    typedef map<ThrottlingHashKey,std::chrono::milliseconds> ThrottlingIntervalsHash;

    bool enabled;
    std::chrono::milliseconds min_interval;
    ThrottlingHash throttling_hash;
    ThrottlingIntervalsHash throttling_intervals_hash;

  public:

    RegShaper()
      : enabled(false)
      , min_interval(std::chrono::milliseconds::zero())
    {}

    /**
     * @brief check if we have to postpone operation
     * @param[in] key key for throttling bucket
     * @param[out] next_attempt_time scheduled time for next attempt for the operation
     * @return true if have to be postponed
     */
    bool check_rate_limit(const ThrottlingHashKey &key,
                          timep &next_attempt_time);
    /**
     * @brief check if we have to postpone operation (with external now timepoint)
     * @param[in] key key for throttling bucket
     * @param[in] now timepoint
     * @param[out] next_attempt_time scheduled time for next attempt for the operation
     * @return true if have to be postponed
     */
    bool check_rate_limit(const ThrottlingHashKey &key,
                          const timep &now,
                          timep &next_attempt_time);

    void set_min_interval(int msec)
    {
        min_interval = std::chrono::milliseconds(msec);
        enabled = true;
    }

    void set_key_min_interval(const string& key, int msec)
    {
        if (min_interval != std::chrono::milliseconds::zero() &&
            min_interval > std::chrono::milliseconds(msec))
        {
            WARN("global restrictions(%u) is more than key's(%s) restrictions(%u)", min_interval, key.c_str(), msec);
        }
        throttling_intervals_hash.emplace(key, std::chrono::milliseconds(msec));
        enabled = true;
    }
};

#pragma once

#include <string>
#include <map>

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

    bool enabled;
    std::chrono::milliseconds min_interval;
    ThrottlingHash throttling_hash;

  public:

    RegShaper()
      : enabled(false)
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
};

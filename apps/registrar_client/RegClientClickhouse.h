#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <AmThread.h>
#include <AmArg.h>

using std::string;
using std::vector;

class RegClientClickhouse {
    bool           clickhouse_enable;
    time_t         last_snapshot_ts;
    string         clickhouse_table;
    string         snapshots_body_header;
    vector<string> clickhouse_dest;
    int            clickhouse_period;

    union {
        uint64_t v;
        struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
            uint64_t counter   : 23;
            uint64_t timestamp : 32;
            uint64_t node_id   : 8;
            uint64_t sign      : 1;
#elif __BYTE_ORDER == __BIG_ENDIAN
            uint64_t sign      : 1;
            uint64_t node_id   : 8;
            uint64_t timestamp : 32;
            uint64_t counter   : 23;
#else
#error "Please fix <bits/endian.h>"
#endif
        } fields;
    } snapshot_id;

  protected:
    AmTimerFd clickhouse_timer;

  public:
    RegClientClickhouse();
    ~RegClientClickhouse() {}

    int configure(const string &config);

    int  init(int epoll_fd);
    void on_timer();

    virtual void getSnapshot(AmArg                                                     &data,
                             std::function<void(unsigned long long value, AmArg &data)> f_enrich_entry) = 0;
};

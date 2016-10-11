#pragma once

#include <stdint.h>


class TimerFD
{
        int             timer_fd;
        int             timer_interval_usec;
        uint64_t        timer_val;

    public:
        TimerFD();
        ~TimerFD();

        bool            init(int epoll_fd, int _timer_interval_usec, int ev_data_fd);
        uint64_t        handler();
        uint64_t        val() { return timer_val; }
        //int             timer_diff(uint64_t from) { return timer_val - from; }
    };

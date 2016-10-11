#include <unistd.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>

#include "timerfd.h"
#include "log.h"


TimerFD::TimerFD()
    : timer_fd (-1), timer_val(0)
{}


TimerFD::~TimerFD()
{
    ::close(timer_fd);
}


void inline set_timespec(struct timespec *tmr, unsigned long long ustime)
{
        tmr->tv_sec = (time_t) (ustime / 1000000ULL);
        tmr->tv_nsec = (long) (1000ULL * (ustime % 1000000ULL));
}


bool TimerFD::init(int epoll_fd, int _timer_interval_usec, int ev_data_fd)
{
    struct itimerspec tmr;


    if( timer_fd >= 0 )
        return true;

    if( (timer_fd = ::timerfd_create( CLOCK_MONOTONIC, TFD_NONBLOCK )) == -1 )
    {
        ERROR("timerfd_create(): %m");
        return false;
    }

    timer_interval_usec = _timer_interval_usec;

    /** N sec interval  */
    set_timespec(&tmr.it_value, timer_interval_usec);
    set_timespec(&tmr.it_interval, timer_interval_usec);

    if(::timerfd_settime(timer_fd, 0, &tmr, NULL))
    {
        ERROR("timerfd_settime(): %m");
        return false;
    }

    struct epoll_event  ev;

    ev.events   = EPOLLIN;
    ev.data.fd  = ev_data_fd;

    if( ::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev) != -1 )
        return true;

    ERROR("%s epoll_ctl(): %m", __func__);
    return false;
}


uint64_t TimerFD::handler()
{
    uint64_t ticks = 0;


    if( ::read(timer_fd, &ticks, sizeof(uint64_t)) == sizeof(uint64_t) )
        timer_val += ticks;
    else
        ERROR("read(): %m");
    return timer_val;
}

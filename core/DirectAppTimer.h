#pragma once

#include "sip/wheeltimer.h"

/* direct timers wrapper for AmAppTimer
 * handles multithreaded timers disarm before fire()
 * and automatically disarms active timer in case with multiple set() calls
 */
class DirectAppTimer
{
    class SharedMutex
      : public AmMutex,
        public atomic_ref_cnt
    { };

    class direct_timer
      : public timer,
        public atomic_ref_cnt
    {
        SharedMutex *mutex;
        DirectAppTimer *owner;
      public:
        direct_timer(DirectAppTimer *t, SharedMutex *shared_mutex);
        virtual ~direct_timer();

        void invalidate();

        //timer interface
        void onDelete() override;
        void fire() override;
    };

    direct_timer *t;
    SharedMutex *mutex;

    void invalidate_timer_unsafe();
    void on_direct_timer_fired(direct_timer *fired_timer);

    virtual void onTimer()=0;

  public:
    DirectAppTimer();
    virtual ~DirectAppTimer();

    DirectAppTimer(const DirectAppTimer&) = delete;
    DirectAppTimer& operator=(const DirectAppTimer&) = delete;

    DirectAppTimer(DirectAppTimer&&) = delete;
    DirectAppTimer& operator=(DirectAppTimer&&) = delete;

    //schedule timer
    void set(double timeout);
    //clear scheduled timer
    void clear();
};

#include "DirectAppTimer.h"
#include "AmAppTimer.h"

DirectAppTimer::direct_timer::direct_timer(DirectAppTimer *owner, SharedMutex *shared_mutex)
 : mutex(shared_mutex),
   owner(owner)
{
    inc_ref(mutex);
}

DirectAppTimer::direct_timer::~direct_timer()
{
    dec_ref(mutex);
}

void DirectAppTimer::direct_timer::invalidate()
{
    owner = nullptr;
}

void DirectAppTimer::direct_timer::onDelete()
{
    //clear wheeltimer reference
    dec_ref(this);
}

void DirectAppTimer::direct_timer::fire()
{
    //will be unlocked in DirectAppTimer::on_direct_timer_fired(direct_timer *fired_timer)
    mutex->lock();

    if(!owner) {
        //deleted timer fired. ignore
        //will be deleted later by wheeltimer::delete_timer(timer *t)
        mutex->unlock();
        return;
    }

    owner->on_direct_timer_fired(this);
}

DirectAppTimer::DirectAppTimer()
  : t(nullptr), mutex(new SharedMutex())
{
    inc_ref(mutex);
}

DirectAppTimer::~DirectAppTimer()
{
    {
        AmLock l(*mutex);
        if(t) {
            t->invalidate();
            AmAppTimer::instance()->remove_timer(t);
            dec_ref(t);
        }
    }
    dec_ref(mutex);
}

void DirectAppTimer::invalidate_timer_unsafe()
{
    if(!t) return;

    t->invalidate();
    AmAppTimer::instance()->remove_timer(t);
    dec_ref(t);
    t = nullptr;
}

void DirectAppTimer::on_direct_timer_fired(direct_timer *fired_timer)
{
    assert(fired_timer==t);

    invalidate_timer_unsafe();

    //locked in direct_timer::fire()
    mutex->unlock();

    onTimer();
}

void DirectAppTimer::set(double timeout)
{

    if(timeout < 0)
        timeout = 0;

    auto new_timer = new direct_timer(this, mutex);
    inc_ref(new_timer); //reference for DirectAppTimer

    new_timer->expires = timeout*1000.0*1000.0 / (double)TIMER_RESOLUTION;
    new_timer->expires += AmAppTimer::instance()->wall_clock;

    {
        AmLock l(*mutex);
        invalidate_timer_unsafe();
        t = new_timer;
    }

    inc_ref(t); //reference for wheeltimer
    AmAppTimer::instance()->insert_timer(t);
}

void DirectAppTimer::clear()
{
    AmLock l(*mutex);
    invalidate_timer_unsafe();
}

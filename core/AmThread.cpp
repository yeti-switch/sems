/*
 * Copyright (C) 2002-2003 Fhg Fokus
 *
 * This file is part of SEMS, a free SIP media server.
 *
 * SEMS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version. This program is released under
 * the GPL with the additional exemption that compiling, linking,
 * and/or using OpenSSL is allowed.
 *
 * For a license to use the SEMS software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * SEMS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "AmThread.h"
#include "AmUtils.h"
#include "log.h"

#include <sys/syscall.h>
#include <unistd.h>
#include "errno.h"
#include <string>
using std::string;

int AmTimerFd::settime(unsigned int umsec, unsigned int repeat_umsec)
{
    struct itimerspec tmr;
    longlong2timespec(tmr.it_value, umsec);
    longlong2timespec(tmr.it_interval, repeat_umsec);
    int res = timerfd_settime(timer_fd, 0, &tmr, nullptr);
    active  = (res == 0 && (tmr.it_value.tv_sec != 0 || tmr.it_value.tv_nsec != 0));
    return res;
}

AmThread::AmThread()
    : _stopped(true)
{
}

AmThread::~AmThread() {}

void AmThread::onIdle() {}

void *AmThread::_start(void *_t)
{
    AmThread *_this    = static_cast<AmThread *>(_t);
    _this->_pid        = static_cast<unsigned long int>(_this->_td);
    _self_pid          = static_cast<pid_t>(GET_PID());
    _self_tid          = static_cast<pthread_t>(GET_TID());
    unsigned long _tid = _this->_pid;

    DBG3("Thread %lu is starting", static_cast<unsigned long>(_tid));

    _this->run();

    char thread_name[16];
    pthread_getname_np(_tid, thread_name, 16);
    DBG3("Thread %s %lu is ending", thread_name, static_cast<unsigned long>(_tid));

    _this->_stopped.set(true);

    return nullptr;
}

void AmThread::start()
{
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1024 * 1024); // 1 MB

    int res;
    _pid = 0;

    // unless placed here, a call seq like run(); join(); will not wait to join
    // b/c creating the thread can take too long
    this->_stopped.lock();
    if (!(this->_stopped.unsafe_get())) {
        this->_stopped.unlock();
        ERROR("thread already running");
        return;
    }
    this->_stopped.unsafe_set(false);
    this->_stopped.unlock();

    res = pthread_create(&_td, &attr, _start, this);
    pthread_attr_destroy(&attr);
    if (res != 0) {
        ERROR("pthread create failed with code %i", res);
        throw string("thread could not be started");
    }
    // DBG("Thread %lu is just created.", (unsigned long int) _pid);
}

void AmThread::stop(bool join_afer_stop)
{
    _m_td.lock();

    if (is_stopped()) {
        _m_td.unlock();
        return;
    }

    char thread_name[16];
    pthread_getname_np(_td, thread_name, 16);

    // gives the thread a chance to clean up
    DBG("Thread %s %lu (%lu)calling on_stop, give it a chance to clean up", thread_name,
        static_cast<unsigned long int>(_pid), static_cast<unsigned long int>(_td));

    try {
        on_stop();
    } catch (...) {
    }

    if (join_afer_stop) {
        DBG("join thread %lu", static_cast<unsigned long int>(_td));
        _m_td.unlock();
        pthread_join(_td, nullptr);
    } else {
        int res;
        if ((res = pthread_detach(_td)) != 0) {
            if (res == EINVAL) {
                WARN("pthread_detach failed with code EINVAL: thread already in detached state");
            } else if (res == ESRCH) {
                DBG("pthread_detach failed with code ESRCH: thread could not be found");
            } else {
                WARN("pthread_detach failed with code %i", res);
            }
        }
        _m_td.unlock();
    }

    DBG("Thread %s %lu (%lu) finished detach", thread_name, static_cast<unsigned long int>(_pid),
        static_cast<unsigned long int>(_td));
}

void AmThread::cancel()
{
    _m_td.lock();

    int res;
    if ((res = pthread_cancel(_td)) != 0) {
        ERROR("pthread_cancel failed with code %i", res);
    } else {
        DBG("Thread %lu is canceled", static_cast<unsigned long int>(_pid));
        _stopped.set(true);
    }

    _m_td.unlock();
}

void AmThread::join()
{
    if (!is_stopped())
        pthread_join(_td, nullptr);
}

int AmThread::setRealtime()
{
    // set process realtime
    //     int policy;
    //     struct sched_param rt_param;
    //     memset (&rt_param, 0, sizeof (rt_param));
    //     rt_param.sched_priority = 80;
    //     int res = sched_setscheduler(0, SCHED_FIFO, &rt_param);
    //     if (res) {
    // 	ERROR("sched_setscheduler failed. Try to run SEMS as root or suid.");
    //     }

    //     policy = sched_getscheduler(0);

    //     std::string str_policy = "unknown";
    //     switch(policy) {
    // 	case SCHED_OTHER: str_policy = "SCHED_OTHER"; break;
    // 	case SCHED_RR: str_policy = "SCHED_RR"; break;
    // 	case SCHED_FIFO: str_policy = "SCHED_FIFO"; break;
    //     }

    //     DBG("Thread has now policy '%s' - priority 80 (from %d to %d).", str_policy.c_str(),
    // 	sched_get_priority_min(policy), sched_get_priority_max(policy));
    //     return 0;
    return 0;
}

void AmThread::setThreadName(const char *thread_name)
{
    _m_td.lock();
    if (thread_name != nullptr && (pthread_setname_np(_td, thread_name) != 0)) {
        WARN("can't set name '%s' for thread %ld[%p] ", thread_name, _td, static_cast<void *>(this));
    }
    _m_td.unlock();
}

AmThreadWatcher *AmThreadWatcher::_instance = nullptr;
AmMutex          AmThreadWatcher::_inst_mut;

AmThreadWatcher::AmThreadWatcher()
    : _run_cond(false)
    , _cleanup(false)
{
}

AmThreadWatcher *AmThreadWatcher::instance()
{
    _inst_mut.lock();
    if (!_instance) {
        _instance = new AmThreadWatcher();
        _instance->start();
    }

    _inst_mut.unlock();
    return _instance;
}

void AmThreadWatcher::add(AmThread *t)
{
    DBG3("trying to add thread %lu to thread watcher", static_cast<unsigned long int>(t->_pid));
    q_mut.lock();
    thread_queue.push(t);
    //_run_cond.set(true);
    q_mut.unlock();
    DBG3("added thread %lu to thread watcher", static_cast<unsigned long int>(t->_pid));
}

void AmThreadWatcher::cleanup()
{
    DBG("cleanup threads garbage collector");
    _cleanup.set(true);
    _run_cond.set(true);
    join();
}

void AmThreadWatcher::on_stop() {}

void AmThreadWatcher::run()
{
    setThreadName("AmThreadWatcher");

    while (!_cleanup.get()) {

        _run_cond.wait_for();

        DBG("Thread watcher starting its work");

        try {
            std::queue<AmThread *> n_thread_queue;

            AmLock l(q_mut);

            while (!thread_queue.empty()) {

                AmThread *cur_thread = thread_queue.front();
                thread_queue.pop();

                DBG("thread %lu is to be processed in thread watcher",
                    static_cast<unsigned long int>(cur_thread->_pid));

                if (_cleanup.get()) {
                    DBG("request thread %lu to stop and join it", static_cast<unsigned long int>(cur_thread->_pid));
                    cur_thread->stop(true);
                }

                if (cur_thread->is_stopped()) {
                    DBG("thread %lu has been destroyed", static_cast<unsigned long int>(cur_thread->_pid));
                    delete cur_thread;
                } else {
                    DBG("thread %lu still running", static_cast<unsigned long int>(cur_thread->_pid));
                    n_thread_queue.push(cur_thread);
                }
            } // while(!thread_queue.empty())

            swap(thread_queue, n_thread_queue);

        } catch (...) {
            /* this one is IMHO very important, as lock is called in try block! */
            ERROR("unexpected exception, state may be invalid!");
        }

        DBG("Thread watcher completed");
        _run_cond.set(thread_queue.empty());
    }

    DBG("Thread watcher finished");
}

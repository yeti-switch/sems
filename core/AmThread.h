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
/** @file AmThread.h */
#pragma once

#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <pthread.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <queue>

#include <mutex>
#include <condition_variable>

#include <string>
using std::string;

#include "log.h"

using AmMutex = std::mutex;
using AmLock  = std::lock_guard<std::mutex>;

/**
 * \brief  Simple lock class witth ability to release mutex onwership
 */
class AmControlledLock {
    AmMutex &m;
    bool     ownership;

  public:
    AmControlledLock(AmMutex &_m)
        : m(_m)
        , ownership(true)
    {
        m.lock();
    }
    AmControlledLock(const AmControlledLock &) = delete;
    ~AmControlledLock()
    {
        if (ownership)
            m.unlock();
    }

    void release_ownership() { ownership = false; }
    void release()
    {
        if (ownership) {
            m.unlock();
            ownership = false;
        }
    }
};

/**
 * \brief Shared variable.
 *
 * Include a variable and its mutex.
 * @warning Don't use safe functions (set,get)
 * within a {lock(); ... unlock();} block. Use
 * unsafe function instead.
 */
template <class T> class AmSharedVar {
    T       t;
    AmMutex m;

  public:
    AmSharedVar(const T &_t)
        : t(_t)
    {
    }
    AmSharedVar(const AmSharedVar &) = delete;
    AmSharedVar() {}

    AmSharedVar &operator=(const AmSharedVar &) = delete;

    T get()
    {
        lock();
        T res = unsafe_get();
        unlock();
        return res;
    }

    void set(const T &new_val)
    {
        lock();
        unsafe_set(new_val);
        unlock();
    }

    void lock() { m.lock(); }
    void unlock() { m.unlock(); }

    const T &unsafe_get() { return t; }
    void     unsafe_set(const T &new_val) { t = new_val; }
};

/**
 * \brief C++ Wrapper class for pthread condition
 */
template <class T> class AmCondition {
    T                       t;
    std::mutex              m;
    std::condition_variable cv;

  public:
    AmCondition()
        : t()
    {
    }
    AmCondition(const T &_t)
        : t(_t)
    {
    }
    AmCondition(const AmCondition &) = delete;

    AmCondition &operator=(const AmCondition &) = delete;

    /** Change the condition's value. */
    void set(const T &newval)
    {
        {
            std::lock_guard lk(m);
            t = newval;
        }

        if (newval)
            cv.notify_all();
    }

    T get()
    {
        std::lock_guard lk(m);
        return t;
    }

    /** Waits for the condition to be true. */
    void wait_for()
    {
        std::unique_lock lk(m);
        cv.wait(lk, [this] { return t; });
    }

    /** Waits for the condition to be true or a timeout. */
    bool wait_for_to(unsigned long msec)
    {
        std::unique_lock lk(m);

        auto ret = cv.wait_for(lk, std::chrono::milliseconds(msec), [this] { return t; });

        if (ret)
            return true;

        return false;
    }
};

/**
 * \brief C++ Wrapper class for event_fd
 */
class AmEventFd {
    int  event_fd;
    int  epoll_fd;
    bool external;

    void add_to_epoll(int fd, bool ptr)
    {
        struct epoll_event ev;
        bzero(&ev, sizeof(struct epoll_event));

        ev.events = EPOLLIN;

        if (ptr)
            ev.data.ptr = this;
        else
            ev.data.fd = -event_fd;

        if (epoll_ctl(fd, EPOLL_CTL_ADD, event_fd, &ev) == -1) {
            throw string("eventfd. epoll_ctl call failed");
        }
    }

  public:
    AmEventFd(bool semaphore = true, bool external_epoll = true)
        : external(external_epoll)
    {
        int flags = EFD_NONBLOCK;
        if (semaphore)
            flags |= EFD_SEMAPHORE;
        if ((event_fd = eventfd(0, flags)) == -1)
            throw string("eventfd. eventfd call failed");
        if (!external) {
            if ((epoll_fd = epoll_create1(0)) == -1)
                throw string("eventfd. epoll_create call failed");
            add_to_epoll(event_fd, false);
        }
    }

    AmEventFd(const AmEventFd &) = delete;

    ~AmEventFd()
    {
        if (!external)
            close(epoll_fd);
        close(event_fd);
    }

    /** Get internal fd */
    operator int() { return -event_fd; }

    /** Add to external epoll handler */
    void link(int fd, bool ptr = false)
    {
        if (!external)
            return;
        add_to_epoll(fd, ptr);
    }

    /** Remove from external epoll handler */
    void unlink(int fd)
    {
        if (!external)
            return;
        epoll_ctl(fd, EPOLL_CTL_DEL, event_fd, nullptr);
    }

    /** Change the condition's value. */
    void fire()
    {
        uint64_t u   = 1;
        ssize_t  ret = write(event_fd, &u, sizeof(uint64_t));
        (void)ret;
    }

    bool read()
    {
        uint64_t u;
        return ::read(event_fd, &u, sizeof(uint64_t)) == sizeof(uint64_t);
    }

    /** Waits for the event or a timeout. */
    bool wait_for(int msec = -1)
    {
        if (external)
            return false;
        struct epoll_event events[1];
        int                ret = epoll_wait(epoll_fd, events, 1, msec);
        return 1 == ret;
    }
};

/**
 * \brief C++ Wrapper class for event_fd
 */
class AmTimerFd {
    int  timer_fd;
    bool active;

    int settime(unsigned int umsec, unsigned int repeat_umsec);

  public:
    AmTimerFd(unsigned int umsec = 0, bool repeat = true)
        : active(false)
    {
        if ((timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK)) == -1)
            throw string("timerfd. timerfd_create call failed");
        if (settime(umsec, repeat ? umsec : 0))
            throw string("timerfd. timer set failed");
    }

    AmTimerFd(const AmTimerFd &) = delete;

    ~AmTimerFd() { close(timer_fd); }

    /** Get internal fd */
    int fd() { return timer_fd; }
    operator int() { return -timer_fd; }

    /** Set time */
    int set(unsigned int umsec, bool repeat = true) { return settime(umsec, repeat ? umsec : 0); }

    /** Set time with explicit repeat interval */
    int set(unsigned int umsec, unsigned int repeat_umsec) { return settime(umsec, repeat_umsec); }

    /** Add to external epoll handler */
    void link(int fd, bool ptr = false)
    {
        struct epoll_event ev;
        bzero(&ev, sizeof(struct epoll_event));
        ev.events = EPOLLIN | EPOLLET;

        if (ptr)
            ev.data.ptr = this;
        else
            ev.data.fd = -timer_fd;

        if (epoll_ctl(fd, EPOLL_CTL_ADD, timer_fd, &ev) == -1) {
            throw string("timerfd. epoll_ctl call failed");
        }
    }

    /** read timer event */
    uint64_t read()
    {
        uint64_t u   = 0;
        ssize_t  ret = ::read(timer_fd, &u, sizeof(uint64_t));
        if (!ret) {
            ERROR("error reading timerfd %d", timer_fd);
        }
        return u;
    }

    /** Remove from external epoll handler */
    void unlink(int fd) { epoll_ctl(fd, EPOLL_CTL_DEL, timer_fd, nullptr); }

    bool is_active() { return active; }
};

/**
 * \brief C++ Wrapper class for pthread
 */
class AmThread {
    pthread_t _td;
    AmMutex   _m_td;

    AmSharedVar<bool> _stopped;

    static void *_start(void *);

  protected:
    virtual void run()     = 0;
    virtual void on_stop() = 0;
    virtual void on_finished() {}

  public:
    unsigned long _pid;

    AmThread();
    virtual ~AmThread();

    virtual void onIdle();

    /** Start it ! */
    void start();
    /** Stop it ! */
    void stop(bool join_afer_stop = false);
    /** @return true if this thread doesn't run. */
    bool is_stopped() { return _stopped.get(); }
    /** Wait for this thread to finish */
    void join();
    /** kill the thread (if pthread_setcancelstate(PTHREAD_CANCEL_ENABLED) has been set) **/
    void cancel();

    int  setRealtime();
    void setThreadName(const char *thread_name);
};

/**
 * \brief Container/garbage collector for threads.
 *
 * AmThreadWatcher waits for threads to stop
 * and delete them.
 * It gets started automatically when needed.
 * Once you added a thread to the container,
 * there is no mean to get it out.
 */
class AmThreadWatcher : public AmThread {
    static AmThreadWatcher *_instance;
    static AmMutex          _inst_mut;

    std::queue<AmThread *> thread_queue;
    AmMutex                q_mut;

    /** the daemon only runs if this is true */
    AmCondition<bool> _run_cond;
    AmCondition<bool> _cleanup;

    AmThreadWatcher();
    void run();
    void on_stop();

  public:
    static AmThreadWatcher *instance();
    void                    add(AmThread *);
    void                    cleanup();
};

template <class T> class AmThreadLocalStorage {
    pthread_key_t key;

    static void __del_tls_obj(void *obj) { delete static_cast<T *>(obj); }

  public:
    AmThreadLocalStorage() { pthread_key_create(&key, __del_tls_obj); }

    AmThreadLocalStorage(const AmThreadLocalStorage &) = delete;

    ~AmThreadLocalStorage() { pthread_key_delete(key); }

    T *get() { return static_cast<T *>(pthread_getspecific(key)); }

    void set(T *p) { pthread_setspecific(key, reinterpret_cast<void *>(p)); }
};

// Local Variables:
// mode:C++
// End:

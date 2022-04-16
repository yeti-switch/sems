/*
 * Copyright (C) 2002-2003 Fhg Fokus
 *
 * This file is part of SEMS, a free SIP media server.
 *
 * SEMS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * For a license to use the sems software under conditions
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

#include "AmMediaProcessor.h"
#include "AmSession.h"
#include "AmRtpStream.h"
#include "AmUtils.h"

#include <assert.h>
#include <sys/time.h>
#include <signal.h>

// Solaris seems to need this for nanosleep().
#if defined (__SVR4) && defined (__sun)
#include <time.h>
#endif

#define CALLGROUPS_SIZE_ESTIMATE 1000

/** \brief Request event to the MediaProcessor (remove,...) */
struct SchedRequest
  : public AmEvent
{
    AmMediaSession* s;

    SchedRequest(int id, AmMediaSession* s)
      : AmEvent(id), s(s)
    {}

    ~SchedRequest();
};

SchedRequest::~SchedRequest()
{}

struct SchedTailRequest
  : public AmEvent
{
    AmMediaTailHandler* h;

    SchedTailRequest(int id, AmMediaTailHandler* h)
      : AmEvent(id), h(h)
    {}

    ~SchedTailRequest();
};

SchedTailRequest::~SchedTailRequest()
{}

/*         session scheduler              */

AmMediaProcessor* AmMediaProcessor::_instance = nullptr;

AmMediaProcessor::AmMediaProcessor()
  : num_threads(0),
    threads(nullptr)
{
    callgroups.reserve(AmConfig.session_limit ?
        AmConfig.session_limit : CALLGROUPS_SIZE_ESTIMATE);
}

AmMediaProcessor::~AmMediaProcessor()
{
    INFO("Media processor has been recycled.\n");
}

void AmMediaProcessor::init()
{
    // start the threads
    num_threads = static_cast<unsigned int>(AmConfig.media_proc_threads);
    assert(num_threads > 0);
    DBG("Starting %u MediaProcessorThreads.\n", num_threads);
    threads = new AmMediaProcessorThread*[num_threads];
    for (unsigned int i=0;i<num_threads;i++) {
        threads[i] = new AmMediaProcessorThread();
        threads[i]->start();
    }
}

AmMediaProcessor* AmMediaProcessor::instance()
{
    if(!_instance)
        _instance = new AmMediaProcessor();

    return _instance;
}

void AmMediaProcessor::addSession(AmMediaSession* s, const string& callgroup)
{
    DBG("AmMediaProcessor::addSession %p",to_void(s));

    // evaluate correct scheduler
    unsigned int sched_thread = 0;

    group_mut.lock();

    if(!s->getMediaCallGroup().empty()) {
        if(callgroup == s->getMediaCallGroup()) {
            DBG("attempt to re-add session %p with callgroup %s. ignore",
                s, callgroup.data());
        } else {
            ERROR("attempt to add session %p to the callgroup %s. actual callgroup:%s. ignore",
                s, callgroup.data(), s->getMediaCallGroup().data());
        }
        group_mut.unlock();
        return;
    }

    s->setMediaCallGroup(
        callgroup.size() ?
            callgroup : AmSession::getNewId());

    // callgroup already in a thread?
    auto it = callgroups.find(s->getMediaCallGroup());
    if(it != callgroups.end()) {
        //yes, use it
        sched_thread = it->second.thread_id;
        //join the callgroup
        it->second.members.emplace(s);
    } else {
        // no, find the thread with lowest load
        unsigned int lowest_load = threads[0]->getLoad();
        for (unsigned int i=1;i<num_threads;i++) {
            unsigned int lower = threads[i]->getLoad();
            if (lower < lowest_load) {
                lowest_load = lower;
                sched_thread = i;
            }
        }

        // create callgroup->thread mapping
        callgroups.try_emplace(s->getMediaCallGroup(), sched_thread, s);
    }

    group_mut.unlock();

    s->onMediaProcessingStarted();

    // add the session to selected thread
    threads[sched_thread]->postRequest(new SchedRequest(InsertSession,s));
}

void AmMediaProcessor::addSession(AmMediaSession* s,
                                  const string &callgroup,
                                  unsigned int sched_thread)
{
    DBG("AmMediaProcessor::addSession %p %u",to_void(s), sched_thread);
    if(sched_thread >= num_threads) {
        ERROR("AmMediaProcessor::addSession: wrong sched_thread %u for session %p",
            sched_thread,to_void(s));
        return;
    }

    group_mut.lock();

    if(!s->getMediaCallGroup().empty()) {
        if(callgroup == s->getMediaCallGroup()) {
            DBG("attempt to re-add session %p with callgroup %s. ignore",
                s, callgroup.data());
        } else {
            ERROR("attempt to add session %p to the callgroup %s. actual callgroup:%s. ignore",
                s, callgroup.data(), s->getMediaCallGroup().data());
        }
        group_mut.unlock();
        return;
    }

    s->setMediaCallGroup(
        callgroup.size() ?
            callgroup : AmSession::getNewId());

    auto it = callgroups.find(s->getMediaCallGroup());
    if(it != callgroups.end()) {
        if(sched_thread != it->second.thread_id) {
            ERROR("callgroup %s exists with different thread_id:%u "
                  "(provided sched_thread:%u). ignore",
                  s->getMediaCallGroup().data(),
                  it->second.thread_id, sched_thread);
            s->clearMediaCallGroup();
            group_mut.unlock();
            return;
        }
        it->second.members.emplace(s);
    } else {
        callgroups.try_emplace(s->getMediaCallGroup(), sched_thread, s);
    }

    group_mut.unlock();

    threads[sched_thread]->postRequest(new SchedRequest(InsertSession,s));
}

void AmMediaProcessor::clearSession(AmMediaSession* s)
{
    removeFromProcessor(s, ClearSession);
}

void AmMediaProcessor::removeSession(AmMediaSession* s)
{
    removeFromProcessor(s, RemoveSession);
}

void AmMediaProcessor::softRemoveSession(AmMediaSession* s)
{
    removeFromProcessor(s, SoftRemoveSession);
}

/* FIXME: implement Call Group ts offsets for soft changing of 
    call groups
*/
void AmMediaProcessor::changeCallgroup(AmMediaSession* s, const string& new_callgroup)
{
    removeFromProcessor(s, SoftRemoveSession);
    addSession(s, new_callgroup);
}

void AmMediaProcessor::removeFromProcessor(AmMediaSession* s, unsigned int r_type)
{
    DBG("AmMediaProcessor::removeSession %p\n",to_void(s));

    group_mut.lock();

    // get scheduler
    auto &callgroup = s->getMediaCallGroup();
    if(callgroup.empty()) {
        group_mut.unlock();
        DBG("attempt to remove session %p without active media callgroup. ignore", s);
        return;
    }

    auto it = callgroups.find(callgroup);
    if(it == callgroups.end()) {
        DBG("callgroup %s not found on session %p removal. clear it and ignore request",
            callgroup.data(), s);
        s->clearMediaCallGroup();
        group_mut.unlock();
        return;
    }

    auto &cg = it->second;
    unsigned int sched_thread = cg.thread_id;

    DBG("  callgroup is '%s', thread %u\n", callgroup.c_str(), sched_thread);

    // erase callgroup membership entry
    auto erased = cg.members.erase(s);
    DBG("erased %ld entries by ptr %p", erased, s);

    // erase callgroup entry if empty
    if(cg.members.empty()) {
        DBG("callgroup empty, erasing it.\n");
        callgroups.erase(it);
    }

    s->clearMediaCallGroup();

    group_mut.unlock();

    threads[sched_thread]->
        postRequest(new SchedRequest(static_cast<int>(r_type),s));
}

void AmMediaProcessor::stop() {
    assert(threads);

    for (unsigned int i=0;i<num_threads;i++) {
        if(threads[i] != nullptr) {
            threads[i]->stop();
        }
    }

    bool threads_stopped = true;
    do {
        usleep(10000); // 10ms
        threads_stopped = true;
        for (unsigned int i=0;i<num_threads;i++) {
            if((threads[i] != nullptr) &&(!threads[i]->is_stopped())) {
                threads_stopped = false;
                break;
            }
        }
    } while(!threads_stopped);

    for (unsigned int i=0;i<num_threads;i++) {
        if(threads[i] != nullptr) {
            delete threads[i];
            threads[i] = nullptr;
        }
    }

    delete []  threads;
    threads = nullptr;
}

void AmMediaProcessor::dispose() 
{
    if(_instance != nullptr) {
        if(_instance->threads != nullptr) {
            _instance->stop();
        }
        delete _instance;
        _instance = nullptr;
    }
}

void AmMediaProcessor::getInfo(AmArg& ret)
{
    group_mut.lock();
    for (unsigned int i=0;i<num_threads;i++) {
        AmMediaProcessorThread *t = threads[i];
        if(!t) continue;
        t->getInfo(ret[int2str(static_cast<unsigned int>(t->_pid))]);
    }
    group_mut.unlock();
}

/* the actual media processing thread */

AmMediaProcessorThread::AmMediaProcessorThread()
  : events(this), stop_requested(false)
{}

AmMediaProcessorThread::~AmMediaProcessorThread()
{}

void AmMediaProcessorThread::on_stop()
{
    INFO("requesting media processor to stop.\n");
    stop_requested.set(true);
}

void AmMediaProcessorThread::run()
{
    setThreadName("media-proc");

    stop_requested = false;
    struct timeval now,next_tick,diff,tick;

    // wallclock time
    ts = 0;//4294417296;

    tick.tv_sec  = 0;
    tick.tv_usec = 1000*WC_INC_MS;

    gettimeofday(&now,nullptr);
    timeradd(&tick,&now,&next_tick);

    while(!stop_requested.get()) {
        gettimeofday(&now,nullptr);

        if(timercmp(&now,&next_tick,<)) {
            struct timespec sdiff,rem;
            timersub(&next_tick,&now,&diff);

            sdiff.tv_sec  = diff.tv_sec;
            sdiff.tv_nsec = diff.tv_usec * 1000;

            if(sdiff.tv_nsec > 2000000) // 2 ms
            nanosleep(&sdiff,&rem);
        }

        processAudio(ts);
        events.processEvents();
        processDtmfEvents();

        ts = (ts + WC_INC) & WALLCLOCK_MASK;
        timeradd(&tick,&next_tick,&next_tick);
    }
}

/**
 * process pending DTMF events
 */
void AmMediaProcessorThread::processDtmfEvents()
{
    for(auto &s : sessions)
        s->processDtmfEvents();
}

void AmMediaProcessorThread::processAudio(unsigned long long ts)
{
    // receiving
    for(auto &s : sessions) {
        if(s->readStreams(ts, buffer) < 0) {
            DBG("readStreams for media session %p returned value < 0",to_void(s));
            postRequest(new SchedRequest(AmMediaProcessor::ClearSession, s));
        }
    }

    // sending
    for(auto &s : sessions) {
        if (s->writeStreams(ts, buffer) < 0) {
            DBG("writeStreams for media session %p returned value < 0",to_void(s));
            postRequest(new SchedRequest(AmMediaProcessor::ClearSession, s));
        }
    }

    // process tail
    for(auto &h : tail_handlers)
        h->processMediaTail(ts);
}

void AmMediaProcessorThread::process(AmEvent* e)
{
    if(SchedRequest* sr = dynamic_cast<SchedRequest*>(e)) {
        switch(sr->event_id){
        case AmMediaProcessor::InsertSession:
            if(sessions.insert(sr->s).second) {
                sr->s->ping(ts);
                sr->s->clearRTPTimeout();
                DBG("[%p] Session %p inserted to the scheduler\n",
                    to_void(this),to_void(sr->s));
            } else {
                DBG("[%p] Session %p has already in scheduler\n",
                    to_void(this),to_void(sr->s));
                sr->s->onMediaSessionExists();
            }
            break;
        case AmMediaProcessor::RemoveSession: {
            AmMediaSession* s = sr->s;
            auto s_it = sessions.find(s);
            if(s_it != sessions.end()) {
                sessions.erase(s_it);
                s->onMediaProcessingTerminated();
                DBG("[%p] Session %p removed from the scheduler on RemoveSession\n",
                    to_void(this),to_void(s));
            }
        } break;
        case AmMediaProcessor::ClearSession: {
            AmMediaSession* s = sr->s;
            set<AmMediaSession*>::iterator s_it = sessions.find(s);
            if(s_it != sessions.end()) {
                sessions.erase(s_it);
                s->clearAudio();
                s->onMediaProcessingTerminated();
                DBG("[%p] Session %p removed from the scheduler on ClearSession\n",
                    to_void(this),to_void(s));
            }
        } break;
        case AmMediaProcessor::SoftRemoveSession: {
            AmMediaSession* s = sr->s;
            set<AmMediaSession*>::iterator s_it = sessions.find(s);
            if(s_it != sessions.end()) {
                sessions.erase(s_it);
                DBG("[%p] Session %p removed softly from the scheduler\n",
                    to_void(this),to_void(s));
            }
        } break;
        default:
            ERROR("AmMediaProcessorThread::process: unknown SchedRequest event id.");
            break;
        } //switch(sr->event_id)
    } else if(SchedTailRequest* sr = dynamic_cast<SchedTailRequest*>(e)) {
        switch(sr->event_id) {
        case AmMediaProcessor::InsertSession:
            tail_handlers.insert(sr->h);
            DBG("[%p] TailHandler %p inserted to the scheduler\n",
                to_void(this),to_void(sr->h));
            break;
        case AmMediaProcessor::RemoveSession: {
            auto h = sr->h;
            auto h_it = tail_handlers.find(h);
            if(h_it != tail_handlers.end()) {
                tail_handlers.erase(h_it);
                h->onMediaTailProcessingTerminated();
                DBG("[%p] TailHandler %p removed from the scheduler on RemoveSession\n",
                    to_void(this),to_void(h));
            }
        } break;
        default:
            ERROR("AmMediaProcessorThread::process: unknown SchedTailRequest event id.");
            break;
        } //switch(sr->event_id)
    } else {
        ERROR("AmMediaProcessorThread::process: wrong event type\n");
    }
}

unsigned int AmMediaProcessorThread::getLoad()
{
    // lock ?
    return static_cast<unsigned int>(sessions.size());
}

void AmMediaProcessorThread::getInfo(AmArg &ret)
{
    ret.assertArray();
    for(auto &s : sessions) {
        AmArg a;
        s->getInfo(a);
        ret.push(a);
    }
}

inline void AmMediaProcessorThread::postRequest(SchedRequest* sr)
{
    events.postEvent(sr);
}

inline void AmMediaProcessorThread::postTailRequest(SchedTailRequest* sr)
{
    events.postEvent(sr);
}

void AmMediaProcessor::addTailHandler(AmMediaTailHandler* h, unsigned int sched_thread)
{
    DBG("AmMediaProcessor::addTailHandler %p to the thread %u",
        to_void(h),sched_thread);
    if(sched_thread >= num_threads) {
        ERROR("AmMediaProcessor::addTailHandler: wrong sched_thread %u for session %p",
            sched_thread,to_void(h));
        return;
    }
    threads[sched_thread]->postTailRequest(new SchedTailRequest(InsertSession,h));
}

void AmMediaProcessor::removeTailHandler(AmMediaTailHandler* h, unsigned int sched_thread)
{
    DBG("AmMediaProcessor::removeTailHandler %p from the thread %u",
        to_void(h),sched_thread);
    if(sched_thread >= num_threads) {
        ERROR("AmMediaProcessor::removeTailHandler: wrong sched_thread %u for session %p",
            sched_thread,to_void(h));
        return;
    }
    h->onMediaTailProcessingStarted();
    threads[sched_thread]->postTailRequest(new SchedTailRequest(RemoveSession,h));
}


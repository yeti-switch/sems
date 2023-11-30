/*
 * $Id: AmSessionProcessor.cpp 1585 2009-10-28 22:31:08Z sayer $
 *
 * Copyright (C) 2010 Stefan Sayer
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

#ifdef SESSION_THREADPOOL

#include "AmSessionProcessor.h"
#include "AmSession.h"

#include <vector>
#include <list>

vector<AmSessionProcessorThread*> AmSessionProcessor::threads;
AmMutex AmSessionProcessor::threads_mut;

vector<AmSessionProcessorThread*>::iterator 
AmSessionProcessor::threads_it = AmSessionProcessor::threads.begin();

AmSessionProcessorIterateRequestContext::AmSessionProcessorIterateRequestContext(
    iterate_func_cb_type icb,
    finish_func_cb_type fcb,
    void* user_data,
    int threads_count)
  : iterate_callback(icb)
  , finish_callback(fcb)
  , user_data(user_data)
{
    aggregated_ret.assertArray(threads_count);
    threads_awaited.set(threads_count);
}

void AmSessionProcessor::init()
{
    stat_group(Counter, "core","session_processor_events_count").addFunctionGroupCounter(&get_statistics_count);
    stat_group(Counter, "core","session_processor_events_time_spent_ms").addFunctionGroupCounter(&get_statistics_time);
}

void AmSessionProcessor::stop()
{
  threads_mut.lock();
  for(auto& thr : threads) {
      thr->stop(true);
      delete thr;
  }
  threads_mut.unlock();
}

AmSessionProcessorThread* AmSessionProcessor::getProcessorThread(bool same) {
  threads_mut.lock();
  if (!threads.size()) {
    ERROR("requesting Session processing thread but none available");
    threads_mut.unlock();
    return NULL;
  }

  if(same) {
    unsigned long id = pthread_self();
    for(auto& thread : threads) {
        if(id == thread->_pid) {
            AmSessionProcessorThread* res = thread;
            threads_mut.unlock();
            return res;
        }
    }
  }

  // round robin
  if (threads_it == threads.end())
    threads_it = threads.begin();

  AmSessionProcessorThread* res = *threads_it;
  threads_it++;
  threads_mut.unlock();
  return res;
}

void AmSessionProcessor::addThreads(unsigned int num_threads) {
  DBG("starting %u session processor threads", num_threads);
  threads_mut.lock();
  for (unsigned int i=0; i < num_threads;i++) {
    threads.push_back(new AmSessionProcessorThread());
    threads.back()->start();
  }
  threads_it = threads.begin();
  DBG("now %zd session processor threads running",  threads.size());
  threads_mut.unlock();
}

void AmSessionProcessor::sendIterateRequest(
    AmSessionProcessorIterateRequestContext::iterate_func_cb_type icb,
    AmSessionProcessorIterateRequestContext::finish_func_cb_type fcb,
    void* callback_ptr)
{
    threads_mut.lock();

    auto ctx = new AmSessionProcessorIterateRequestContext(
        icb, fcb, callback_ptr, threads.size());

    int i = 0;
    for(auto &t : threads)
        t->sendIterateRequest(
            new AmSessionProcessorIterateRequestEvent(
                ctx, i++));

    threads_mut.unlock();
}

void AmSessionProcessor::get_statistics_count(StatCounterInterface::iterate_func_type f)
{
    //event_stats.iterate_count(f);
    for(auto &t : threads)
        t->get_statistics_count(f);
}

void AmSessionProcessor::get_statistics_time(StatCounterInterface::iterate_func_type f)
{
    //event_stats.iterate_time(f);
    for(auto &t : threads)
        t->get_statistics_time(f);

}

AmSessionProcessorThread::AmSessionProcessorThread()
  : events(this), runcond(false)
{}

AmSessionProcessorThread::~AmSessionProcessorThread() {
}

void AmSessionProcessorThread::notify(AmEventQueue* sender) {
  process_sessions_mut.lock();
  runcond.set(true);
  process_sessions.insert(sender);
  process_sessions_mut.unlock();
}

void AmSessionProcessorThread::run()
{
    setThreadName("session-proc");

    event_stats.addLabel("thread",int2str(gettid()));

    stop_requested = false;
    while(true) {

        DBG("running processing loop");

        runcond.wait_for();

        if(stop_requested.get()) break;

        process_sessions_mut.lock();
        runcond.set(false);

        // get the list of session s that need processing
        std::set<AmEventQueue*> pending_process_sessions = process_sessions;
        process_sessions.clear();

        process_sessions_mut.unlock();

        // process control events (AmSessionProcessorThreadAddEvent)
        events.processEvents();

        // startup all new sessions
        if (!startup_sessions.empty()) {
            DBG("starting up %zd sessions", startup_sessions.size());

            for (std::vector<AmSession*>::iterator it = startup_sessions.begin();
                 it != startup_sessions.end(); it++)
            {
                DBG("starting up [%s|%s]: [%p]",
                    (*it)->getCallID().c_str(), (*it)->getLocalTag().c_str(),*it);

                if ((*it)->startup()) {
                    sessions.push_back(*it); // startup successful
                    // make sure this session is being processed for startup events
                    pending_process_sessions.insert(*it);
                }
            }
            startup_sessions.clear();
        }

        std::vector<AmSession*> fin_sessions;

        DBG("processing events for  up to %zd sessions", pending_process_sessions.size());

        std::list<AmSession*>::iterator it=sessions.begin();
        event_stats_mutex.lock();
        while (it != sessions.end()) {
            if ((pending_process_sessions.find(*it)!=pending_process_sessions.end())
                && (!(*it)->processingCycle(&event_stats)))
            {
                fin_sessions.push_back(*it);
                std::list<AmSession*>::iterator d_it = it;
                it++;
                sessions.erase(d_it);
            } else {
                it++;
            }
        }
        event_stats_mutex.unlock();

        if (fin_sessions.size()) {
            DBG("finalizing %zd sessions", fin_sessions.size());
            for (std::vector<AmSession*>::iterator it=fin_sessions.begin();
                 it != fin_sessions.end(); it++)
            {
                DBG("finalizing session [%p/%s/%s]",
                    *it, (*it)->getCallID().c_str(), (*it)->getLocalTag().c_str());

                (*it)->finalize();
            }
        }
    } //while(!stop_requested.get())
}

void AmSessionProcessorThread::on_stop() {
  INFO("requesting session to stop.");
  stop_requested.set(true);
  runcond.set(true);
}

// AmEventHandler interface
void AmSessionProcessorThread::process(AmEvent* e)
{
    AmSessionProcessorThreadAddEvent* add_ev =
        dynamic_cast<AmSessionProcessorThreadAddEvent*>(e);

    if (nullptr!=add_ev) {
        startup_sessions.push_back(add_ev->s);
        return;
    }

    if (auto req_ev =
            dynamic_cast<AmSessionProcessorIterateRequestEvent*>(e))
    {
        auto ctx = req_ev->ctx;

        //apply callback for all sessions
        for(auto &session: sessions) {
            ctx->iterate_callback(
                session,
                ctx->user_data,
                req_ev->ret);
        }

        if(ctx->threads_awaited.dec_and_test()) {
            //this thread is the last that finished the iteration
            ctx->finish_callback(
                ctx->aggregated_ret,
                ctx->user_data);

            delete ctx;
        }

        return;
    }

    ERROR("received wrong event in AmSessionProcessorThread");
}

void AmSessionProcessorThread::startSession(AmSession* s) {
  // register us to be notified if some event comes to the session
  s->setEventNotificationSink(this);

  // add this to be scheduled
  events.postEvent(new AmSessionProcessorThreadAddEvent(s));

  // trigger processing of events already in queue at startup
  notify(s);

  // wakeup the thread
  runcond.set(true);
}

void AmSessionProcessorThread::sendIterateRequest(AmSessionProcessorIterateRequestEvent* req)
{
  events.postEvent(req);
  runcond.set(true);
}

void AmSessionProcessorThread::get_statistics_count(StatCounterInterface::iterate_func_type f)
{
    AmLock l(event_stats_mutex);
    event_stats.iterate_count(f);
}

void AmSessionProcessorThread::get_statistics_time(StatCounterInterface::iterate_func_type f)
{
    AmLock l(event_stats_mutex);
    event_stats.iterate_time(f);
}

#endif

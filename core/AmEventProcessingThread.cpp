/*
 * Copyright (C) 2011 Stefan Sayer
 *
 * This file is part of SEMS, a free SIP media server.
 *
 * SEMS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

#include "AmEventProcessingThread.h"
#include "log.h"

AmEventProcessingThread::AmEventProcessingThread()
    : AmEventQueue(this)
    , processing_events(true)
{
}

AmEventProcessingThread::~AmEventProcessingThread() {}

bool AmEventProcessingThread::police_event(AmEvent *ev)
{
    // default: accept all events
    return true;
}

void AmEventProcessingThread::postEvent(AmEvent *ev)
{
    if (police_event(ev)) {
        AmEventQueue::postEvent(ev);
    } else {
        DBG("dropping event [%p] due to policing", ev);
        delete ev;
    }
}

void AmEventProcessingThread::on_stop()
{
    DBG("AmEventProcessingThread::on_stop");
}

void AmEventProcessingThread::run()
{
    setThreadName("AmEvt");
    DBG("AmEventProcessingThread running...");

    while (processing_events) {
        waitForEvent();
        processEvents();
    }

    DBG("AmEventProcessingThread stopping.");
}

void AmEventProcessingThread::stop_processing()
{
    DBG("stop of event processing requested.");
    processing_events = false;
}

void AmEventProcessingThread::process(AmEvent *ev)
{

    // check for shutdown
    if (ev->event_id == E_SYSTEM) {
        AmSystemEvent *sys_ev = dynamic_cast<AmSystemEvent *>(ev);
        if (sys_ev) {
            DBG("received system Event");
            if (sys_ev->sys_event == AmSystemEvent::ServerShutdown) {
                DBG("received system Event: ServerShutdown. Stopping event processing.");
                processing_events = false;
            }
        }
    }

    onEvent(ev);
}

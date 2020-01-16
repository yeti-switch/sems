/*
 * Copyright (C) 2010 Stefan Sayer
 * Copyright (C) 2011 Raphael Coeffic
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

#pragma once

#include "AmThread.h"
#include <atomic>
#include <queue>
using std::queue;

class AmRtpStream;

class AmDtmfSender
{
    struct Dtmf {
        int event;
        unsigned int duration_ms;
        unsigned int sample_rate;
        unsigned int frame_size;
        Dtmf() = default;
        Dtmf(int event, unsigned int duration_ms,
            unsigned int sample_rate,
            unsigned int frame_size)
          : event(event),
            duration_ms(duration_ms),
            sample_rate(sample_rate),
            frame_size(frame_size)
        {}
    };

    enum sending_state_t {
        DTMF_SEND_NONE,             // not sending event
        DTMF_SEND_SENDING_FIRST,    // sending event first packet
        DTMF_SEND_SENDING,          // sending event
        DTMF_SEND_ENDING            // sending end of event
    } sending_state;
    std::atomic_bool is_sending;

    queue<Dtmf> send_queue;
    AmMutex     send_queue_mut;

    Dtmf         current_event;
    //user timestamp of the event sending started
    unsigned int current_send_dtmf_ts;
    //timestamp used to get duration value for event
    unsigned int current_send_dtmf_duration_ts;
    //event duration in timestamp values
    unsigned int send_dtmf_duration_ts;
    //timestamp to stop event sending
    unsigned int send_dtmf_end_ts;
    //counter to send ending packets
    int          send_dtmf_end_repeat;

  public:
    AmDtmfSender();

    bool isSending() { return is_sending.load(); }

    /** Add a DTMF event to the send queue */
    void queueEvent(int event, unsigned int duration_ms, unsigned int sample_rate, unsigned int frame_size);

    /** Processes the send queue according to the timestamp */
    bool sendPacket(unsigned int ts, unsigned int remote_pt, AmRtpStream* stream);
};


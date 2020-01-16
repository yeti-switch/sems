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

#include "AmDtmfSender.h"
#include "AmRtpStream.h"

#include "rtp/telephone_event.h"

#define DTMF_EVENT_MIN_DURATION 160

#define DTMF_SENDER_PACKET_SENT true
#define DTMF_SENDER_NOP false

AmDtmfSender::AmDtmfSender()
  : sending_state(DTMF_SEND_NONE),
    is_sending(false)
{ }

/** Add a DTMF event to the send queue */
void AmDtmfSender::queueEvent(
    int event,
    unsigned int duration_ms,
    unsigned int sample_rate, unsigned int frame_size)
{
    send_queue_mut.lock();
    send_queue.emplace(event, duration_ms, sample_rate, frame_size);
    send_queue_mut.unlock();
    DBG("enqueued DTMF event %i duration %u frame_size: %u queue: %p, size: %lu",
        event, duration_ms, frame_size,
        to_void(&send_queue), send_queue.size());
}

/** Processes the send queue according to the timestamp */
bool AmDtmfSender::sendPacket(unsigned int ts, unsigned int remote_pt, AmRtpStream* stream)
{
    do {
        switch(sending_state) {
        case DTMF_SEND_NONE: {
            send_queue_mut.lock();
            if (send_queue.empty()) {
                send_queue_mut.unlock();
                return DTMF_SENDER_NOP;
            }

            DBG("DTMF_SEND_NONE queue: %p, size = %lu",
                static_cast<void *>(&send_queue), send_queue.size());

            current_event = send_queue.front();
            send_queue.pop();
            send_queue_mut.unlock();

            sending_state = DTMF_SEND_SENDING_FIRST;
            send_dtmf_duration_ts = current_event.duration_ms * current_event.sample_rate / 1000;
            unsigned int frame_size_ts = current_event.frame_size * current_event.sample_rate / 1000;

            DBG("current_event.duration_ms: %u, current_event.frame_size: %u, frame_size_ms: %u, send_dtmf_duration_ts: %u",
                current_event.duration_ms, current_event.frame_size, frame_size_ts, send_dtmf_duration_ts);

            if(send_dtmf_duration_ts < frame_size_ts) {
                send_dtmf_duration_ts = frame_size_ts;
                DBG("dtmf event duration %u is less than %u. set it to %u",
                    send_dtmf_duration_ts,
                    frame_size_ts, frame_size_ts);
            }

            current_send_dtmf_ts = ts;
            current_send_dtmf_duration_ts = current_send_dtmf_ts - frame_size_ts;
            send_dtmf_end_ts = ts + send_dtmf_duration_ts;

            DBG("starting to send DTMF. key: %d, duration: %u, current_send_dtmf_ts: %u, send_dtmf_end_ts: %u",
                current_event.event, send_dtmf_duration_ts,
                current_send_dtmf_ts, send_dtmf_end_ts);

            is_sending.store(true);
        } break;
        case DTMF_SEND_SENDING_FIRST:
        case DTMF_SEND_SENDING: {
            if (ts_less()(ts, send_dtmf_end_ts)) {

                // send packet
                u_int16 duration = static_cast<u_int16>(ts - current_send_dtmf_duration_ts);

                dtmf_payload_t dtmf;
                dtmf.event = static_cast<u_int8>(current_event.event);
                dtmf.e = dtmf.r = 0;
                dtmf.duration = htons(duration);
                dtmf.volume = 20;

                DBG("DTMF_SEND_SENDING: ts:%u send: event=%i; e=%i; r=%i; volume=%i; duration=%i; ts=%u\n",
                    ts, dtmf.event,dtmf.e,dtmf.r,dtmf.volume,duration,current_send_dtmf_ts);

                stream->compile_and_send(
                    static_cast<int>(remote_pt),
                    sending_state == DTMF_SEND_SENDING_FIRST,
                    current_send_dtmf_ts,
                    reinterpret_cast<unsigned char*>(&dtmf), sizeof(dtmf_payload_t));

                if(sending_state == DTMF_SEND_SENDING_FIRST)
                    sending_state = DTMF_SEND_SENDING;

                return DTMF_SENDER_PACKET_SENT;
            } else {
                sending_state = DTMF_SEND_ENDING;
                send_dtmf_end_repeat = 0;
            }
        } break;
        case DTMF_SEND_ENDING: {
            if (send_dtmf_end_repeat >= 3) {
                DBG("DTMF send complete\n");
                sending_state = DTMF_SEND_NONE;
                is_sending.store(false);
            } else {
                send_dtmf_end_repeat++;

                // send packet with end bit set, duration = event duration
                dtmf_payload_t dtmf;
                dtmf.event = static_cast<u_int8>(current_event.event);
                dtmf.e = 1;
                dtmf.r = 0;
                dtmf.duration = htons(send_dtmf_duration_ts);
                dtmf.volume = 20;

                DBG("sending DTMF: event=%i; e=%i; r=%i; volume=%i; duration=%i; ts=%u\n",
                    dtmf.event,dtmf.e,dtmf.r,dtmf.volume,ntohs(dtmf.duration),current_send_dtmf_ts);

                stream->compile_and_send(
                    static_cast<int>(remote_pt),
                    false,
                    current_send_dtmf_ts,
                    reinterpret_cast<unsigned char*>(&dtmf), sizeof(dtmf_payload_t));
                return DTMF_SENDER_PACKET_SENT;
            }
        } break;
        }; //switch(sending_state)
    } while(true);
}


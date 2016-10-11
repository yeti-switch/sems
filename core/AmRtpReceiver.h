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
/** @file AmRtpReceiver.h */
#ifndef _AmRtpReceiver_h_
#define _AmRtpReceiver_h_

#include "AmThread.h"
#include "atomic_types.h"
#include "singleton.h"

#include <sys/epoll.h>

#include <map>
#include <list>
using std::greater;

#include <cstring>

class AmRtpStream;
class _AmRtpReceiver;

#ifndef MAX_RTP_SESSIONS
#define MAX_RTP_SESSIONS 2048
#endif

//!TODO: implement using bit map
template <unsigned int len>
class UsageMap {
    bool bits[len];
  public:
    UsageMap() {
        memset(bits, 0, len);
    }

    int get_free_idx(){
        bool *e = bits;
        unsigned int idx = 0;
        for(; idx < len; idx++, e++){
            if(!*e){
                *e = true;
                return idx;
            }
        }
        return -1;
    }

    void clear_idx(int idx){
        bits[idx] = false;
    }

    bool used(int idx){
        return bits[idx];
    }
};

class StreamCtxMap {
  public:
    struct StreamCtx {
        bool valid;
        int stream_fd;
        AmRtpStream* stream;
        StreamCtx(): valid(false) {}
    };
  private:
    UsageMap<MAX_RTP_SESSIONS> usage;
    StreamCtx ctxs[MAX_RTP_SESSIONS];
    std::list<int> ctxs_to_put;
  public:
    StreamCtxMap() {}
    int ctx_get(int fd, AmRtpStream* s);
    void ctx_put(int ctx_idx);
    void ctx_put_immediate(int ctx_idx);
    bool is_double_add(int old_ctx_idx, AmRtpStream *stream);
    void recv(int ctx_idx);
    void put_pended();
};

/**
 * \brief receiver for RTP for all streams.
 *
 * The RtpReceiver receives RTP packets for all streams 
 * that are registered to it. It places the received packets in 
 * the stream's buffer. 
 */
class AmRtpReceiverThread: public AmThread {

  StreamCtxMap streams;
  AmMutex  streams_mut;
  AmEventFd stop_event;
  AmEventFd stream_remove_event;

  int poll_fd;

  AmRtpReceiverThread();
  ~AmRtpReceiverThread();
    
  void run();
  void on_stop();

  int addStream(int sd, AmRtpStream* stream, int old_ctx_idx);
  void removeStream(int sd, int ctx_idx);

  void stop_and_wait();

  friend class _AmRtpReceiver;
};

class _AmRtpReceiver
{
  AmRtpReceiverThread* receivers;
  unsigned int         n_receivers;

  atomic_int next_index;

protected:
  _AmRtpReceiver();
  ~_AmRtpReceiver();

  void dispose();

public:
  void start();

  int addStream(int sd, AmRtpStream* stream, int old_ctx_idx);
  void removeStream(int sd, int ctx_idx);
};

typedef singleton<_AmRtpReceiver> AmRtpReceiver;

#endif

// Local Variables:
// mode:C++
// End:

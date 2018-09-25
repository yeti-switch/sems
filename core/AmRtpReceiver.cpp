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

#include "AmRtpReceiver.h"
#include "log.h"

#include <errno.h>

// Not on Solaris!
#if !defined (__SVR4) && !defined (__sun)
#include <strings.h>
#endif

#include <sys/time.h>
#include <sys/epoll.h>
#include "AmLcConfig.h"

#define EPOLL_MAX_EVENTS 2048

int StreamCtxMap::ctx_get(int fd, AmRtpSession* s){
    int idx = usage.get_free_idx();
    if(-1==idx) return -1;

    StreamCtx &ctx = ctxs[idx];

    ctx.stream_fd = fd;
    ctx.stream = s;
    ctx.valid = true;
    //CLASS_DBG("ctx_get(%d, %p) = %d",fd,s,idx);
    return idx;
}

void StreamCtxMap::ctx_put(int ctx_idx){
    ctxs[ctx_idx].valid = false;
    ctxs_to_put.push_back(ctx_idx);
}

void StreamCtxMap::ctx_put_immediate(int ctx_idx){
    ctxs[ctx_idx].valid = false;
    usage.clear_idx(ctx_idx);
}

bool StreamCtxMap::is_double_add(int old_ctx_idx, AmRtpSession *stream){
    return (-1!=old_ctx_idx) && (ctxs[old_ctx_idx].stream==stream);
}

void StreamCtxMap::recv(int ctx_idx){
    StreamCtx &ctx = ctxs[ctx_idx];
    if(ctx.valid){
        ctx.stream->recvPacket(ctx.stream_fd);
    } else {
        ctxs_to_put.push_back(ctx_idx);
    }
}

void StreamCtxMap::put_pended(){
    while(!ctxs_to_put.empty()){
        //CLASS_DBG("put pended %d",ctxs_to_put.front());
        usage.clear_idx(ctxs_to_put.front());
        ctxs_to_put.pop_front();
    }
}

_AmRtpReceiver::_AmRtpReceiver()
{
  n_receivers = AmConfig_.rtp_recv_threads;
  receivers = new AmRtpReceiverThread[n_receivers];
}

_AmRtpReceiver::~_AmRtpReceiver()
{
  delete [] receivers;
}

AmRtpReceiverThread::AmRtpReceiverThread()
  : poll_fd(-1) { }

AmRtpReceiverThread::~AmRtpReceiverThread()
{
  INFO("RTP receiver has been recycled.\n");
}

void AmRtpReceiverThread::on_stop()
{
  INFO("requesting RTP receiver to stop.\n");
  stop_event.fire();
}

void AmRtpReceiverThread::stop_and_wait()
{
  if(!is_stopped()) {
    stop();
    
    while(!is_stopped()) 
      usleep(10000);
  }
}

void _AmRtpReceiver::dispose() 
{
  for(unsigned int i=0; i<n_receivers; i++){
    receivers[i].stop_and_wait();
  }
}

void AmRtpReceiverThread::run()
{
  struct epoll_event events[EPOLL_MAX_EVENTS];

  poll_fd = epoll_create(EPOLL_MAX_EVENTS);
  if (poll_fd == -1) {
    throw string("failed epoll_create in AmRtpReceiverThread: "+string(strerror(errno)));
  }

  stop_event.link(poll_fd);
  stream_remove_event.link(poll_fd);

  setThreadName("rtp-rx");

  bool stop = false;
  while(!stop){
    int ret = epoll_wait(poll_fd,events,EPOLL_MAX_EVENTS,-1);
    if(ret == -1 && errno != EINTR){
      ERROR("AmRtpReceiver: epoll_wait: %s\n",strerror(errno));
    }
    if(ret < 1)
      continue;

    streams_mut.lock();
    for (int n = 0; n < ret; ++n) {
      struct epoll_event &e = events[n];
      if(!(e.events & EPOLLIN)){
        continue;
      }
      if(e.data.fd==stop_event){
          stop_event.read();
          stop = true;
          break;
      }
      if(e.data.fd==stream_remove_event){
          stream_remove_event.read();
          /* do nothing. this event is fired just to ensure that
           * streams.put_pended(ctxs) will be called even if
           * no rtp packets will be received */
          continue;
      }
      streams.recv(e.data.fd);
    }
    streams.put_pended();
    streams_mut.unlock();
  } //while(!stop)
  close(poll_fd);
}

int AmRtpReceiverThread::addStream(int sd, AmRtpSession* stream, int old_ctx_idx)
{
  AmLock l(streams_mut);
  (void)l;

  if(streams.is_double_add(old_ctx_idx,stream)){
      DBG("atempt to add already added stream. return back old ctx");
      return old_ctx_idx;
  }

  int ctx_idx = streams.ctx_get(sd,stream);
  if(-1==ctx_idx){
      ERROR("streams contexts storage exhausted");
      throw string("streams contexts storage exhausted");
  }
  struct epoll_event ev;
  bzero(&ev, sizeof(struct epoll_event));
  ev.events = EPOLLIN;
  ev.data.fd = ctx_idx;
  if(epoll_ctl(poll_fd,EPOLL_CTL_ADD,sd,&ev)==-1){
    ERROR("failed to add to epoll structure stream [%p] with sd=%i, ctx_idx = %d error: %s\n",
        stream,sd,ctx_idx,strerror(errno));
    streams.ctx_put_immediate(ctx_idx);
    return -1;
  }
  return ctx_idx;
}

void AmRtpReceiverThread::removeStream(int sd, int ctx_idx)
{
  if(ctx_idx == -1) return;

  AmLock l(streams_mut);
  (void)l;

  if(epoll_ctl(poll_fd,EPOLL_CTL_DEL,sd,NULL)==-1){
      ERROR("removeStream epoll_ctl_del sd = %i error %s",
            sd,strerror(errno));
      //FIXME: maybe we should put context even after epoll del failure
      return;
  }
  streams.ctx_put(ctx_idx);
  stream_remove_event.fire();
}

void _AmRtpReceiver::start()
{
  for(unsigned int i=0; i<n_receivers; i++)
    receivers[i].start();
}

int _AmRtpReceiver::addStream(int sd, AmRtpSession* stream, int old_ctx_idx)
{
  unsigned int i = sd % n_receivers;
  return receivers[i].addStream(sd,stream,old_ctx_idx);
}

void _AmRtpReceiver::removeStream(int sd, int ctx_idx)
{
  unsigned int i = sd % n_receivers;
  receivers[i].removeStream(sd,ctx_idx);
}

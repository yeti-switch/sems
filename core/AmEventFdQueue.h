/** @file AmEventFdQueue.h */
#ifndef _AMEVENTFDQUEUE_H_
#define _AMEVENTFDQUEUE_H_

#include "AmThread.h"
#include "AmEvent.h"
#include "AmEventQueue.h"
#include "atomic_types.h"

#include <queue>

class AmEventFdQueue
  : public AmEventQueueInterface,
    public atomic_ref_cnt
{
protected:
  AmEventHandler*           handler;

  std::queue<AmEvent*>      ev_queue;
  AmMutex                   m_queue;

  int event_fd;

  bool finalized;

public:
  AmEventFdQueue(AmEventHandler* handler);
  virtual ~AmEventFdQueue();

  void postEvent(AmEvent*);
  void processEvents();
  void processSingleEvent();
  bool eventPending();

  void epoll_link(int epoll_fd, bool ptr = false);
  void epoll_unlink(int epoll_fd);

  void clear_pending();

  int operator()() { return -event_fd; }
  int queue_fd() { return event_fd; }

  bool is_finalized() { return finalized; }

  // return true to continue processing
  virtual bool startup() { return true; }
  virtual bool processingCycle() { processEvents(); return true; }
  virtual void finalize() { finalized = true; }
};

#endif


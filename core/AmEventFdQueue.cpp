#include "AmEventFdQueue.h"
#include "log.h"
#include "AmLcConfig.h"

#include <typeinfo>
AmEventFdQueue::AmEventFdQueue(AmEventHandler* handler)
  : handler(handler),
    finalized(false)
{
    if( (event_fd = eventfd(0, EFD_NONBLOCK)) == -1)
      throw string("eventfd. eventfd call failed");
}

AmEventFdQueue::~AmEventFdQueue()
{
  m_queue.lock();
  while(!ev_queue.empty()){
    delete ev_queue.front();
    ev_queue.pop();
  }
  m_queue.unlock();
}

void AmEventFdQueue::postEvent(AmEvent* event)
{
  uint64_t u = 1;

  if (AmConfig.log_events) 
    DBG("AmEventQueue: trying to post event");

  m_queue.lock();

  if(event)
    ev_queue.push(event);

  ssize_t ret = ::write(event_fd, &u, sizeof(uint64_t));
  (void)ret;

  m_queue.unlock();

  if (AmConfig.log_events) 
    DBG("AmEventQueue: event posted");
}

void AmEventFdQueue::processEvents()
{
    m_queue.lock();

    while(!ev_queue.empty()) {
        std::unique_ptr<AmEvent> event(ev_queue.front());
        ev_queue.pop();
        m_queue.unlock();

        auto& event_ref = *event.get();

        if(AmConfig.log_events)
            DBG("before processing event (%s)", typeid(event_ref).name());

        auto consumed = handler->process_consuming(event.get());

        if(AmConfig.log_events)
            DBG("event processed");

        if(consumed) event.release();

        m_queue.lock();
    }

    clear_pending();

    m_queue.unlock();
}

void AmEventFdQueue::processSingleEvent()
{
    m_queue.lock();

    if (!ev_queue.empty()) {

      AmEvent* event = ev_queue.front();
      ev_queue.pop();
      m_queue.unlock();

      if (AmConfig.log_events)
        DBG("before processing event");

      if(!handler->process_consuming(event))
        delete event;

      if (AmConfig.log_events)
        DBG("event processed");

      m_queue.lock();
    }

    m_queue.unlock();
}

bool AmEventFdQueue::eventPending() {
  m_queue.lock();
  bool res = !ev_queue.empty();
  m_queue.unlock();
  return res;
}

void AmEventFdQueue::epoll_link(int epoll_fd, bool ptr)
{
    struct epoll_event ev;
    bzero(&ev, sizeof(struct epoll_event));
    ev.events = EPOLLIN;
    if(ptr) ev.data.ptr = this;
    else ev.data.fd = -event_fd;
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event_fd, &ev) == -1){
      throw string("eventfd. epoll_ctl call failed");
    }
}

void AmEventFdQueue::epoll_unlink(int epoll_fd)
{
    epoll_ctl(epoll_fd,EPOLL_CTL_DEL,event_fd,NULL);
}

void AmEventFdQueue::clear_pending()
{
    uint64_t u;
    ssize_t ret = ::read(event_fd, &u, sizeof(uint64_t));
    (void)ret;
}

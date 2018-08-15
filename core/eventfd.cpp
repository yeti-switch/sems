#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <string.h>

#include "eventfd.h"
#include "log.h"


EventFD::EventFD()
    : event_fd(-1)
{}

EventFD::~EventFD()
{
    ::close(event_fd);
}


bool EventFD::init(int epoll_fd, int flags, int ev_data_fd)
{
    if( event_fd >= 0 )
        return true;

    if( (event_fd = ::eventfd(0, flags | EFD_NONBLOCK)) == -1)
    {
        ERROR("eventfd(): %m");
        return false;
    }


    struct epoll_event  ev;

    bzero(&ev,sizeof(struct epoll_event));
    ev.events   = EPOLLIN;
    ev.data.fd  = ev_data_fd;


    if( ::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event_fd, &ev) != -1 )
        return true;

    ERROR("%s epoll_ctl(): %m", __func__);
    return false;
}


void EventFD::handler()
{
    uint64_t u;

    if( ::read(event_fd, &u, sizeof(uint64_t)) != sizeof(uint64_t) )
        ERROR("read(): %m");
}


void EventFD::pushEvent(void)
{
    uint64_t u = 1;

    if( ::write(event_fd, &u, sizeof(uint64_t)) != sizeof(uint64_t) )
        ERROR("write(): %m");
}

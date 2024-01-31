#include "RegistrarHandler.h"
#include "log.h"
#include "AmEventDispatcher.h"
#include <gtest/gtest.h>

#define EPOLL_MAX_EVENTS    2048

RegistrarHandler* RegistrarHandler::_instance = NULL;

RegistrarHandler* RegistrarHandler::instance()
{
    if(_instance == nullptr){
        _instance = new RegistrarHandler();
    }
    return _instance;
}

void RegistrarHandler::dispose()
{
    if(_instance != nullptr){
        delete _instance;
    }
    _instance = nullptr;
}

RegistrarHandler::RegistrarHandler()
    : AmEventFdQueue(this)
{
    epoll_fd = epoll_create(10);
    epoll_link(epoll_fd, true);
    stop_event.link(epoll_fd,true);

    AmEventDispatcher::instance()->addEventQueue(REGISTRAR_HANDLER_QUEUE, this);
}

RegistrarHandler::~RegistrarHandler()
{
    AmEventDispatcher::instance()->delEventQueue(REGISTRAR_HANDLER_QUEUE);
    epoll_unlink(epoll_fd);
    close(epoll_fd);
}

void RegistrarHandler::run()
{
    void *p;
    bool running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    running = true;
    do {
        int ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, 3000);

        if(ret == -1 && errno != EINTR){
            GTEST_FATAL_FAILURE_("epoll_wait error");
            break;
        }

        if(ret < 1) {
            GTEST_FATAL_FAILURE_("expected event has not got");
            break;
        }

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            p = e.data.ptr;

            if(p==static_cast<AmEventFdQueue *>(this)){
                processEvents();
            } else if(p==&stop_event){
                stop_event.read();
                running = false;
                break;
            }
        }

    } while(running);

    DBG("RegistrarHandler stopped");
    stopped.set(true);
}

void RegistrarHandler::on_stop()
{
    stop_event.fire();
    stopped.wait_for();
}

void RegistrarHandler::process(AmEvent* event)
{
    switch(event->event_id) {
        case E_SYSTEM: {
            AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(event);
            if(sys_ev && sys_ev->sys_event == AmSystemEvent::ServerShutdown) {
                stop_event.fire();
            }
            return;
        }
    }

    if(handle_event) {
        handle_event(event);
        handle_event = nullptr;
    }

    stop_event.fire();
}

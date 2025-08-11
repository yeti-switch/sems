#include "TestClient.h"

#include <log.h>
#include <AmEventDispatcher.h>
#include <gtest/gtest.h>

#define EPOLL_MAX_EVENTS 2048

TestClient::TestClient()
    : TestClient(TEST_CLIENT_QUEUE)
{
}

TestClient::TestClient(const string &queue_name)
    : AmEventFdQueue(this)
    , queue_name(queue_name)
{
    epoll_fd = epoll_create(10);
    epoll_link(epoll_fd, true);
    stop_event.link(epoll_fd, true);
    AmEventDispatcher::instance()->addEventQueue(queue_name, this);
}

TestClient::~TestClient()
{
    AmEventDispatcher::instance()->delEventQueue(queue_name);
    epoll_unlink(epoll_fd);
    close(epoll_fd);
}

void TestClient::reset()
{
    reply_available.set(false);
    reply_data      = 0;
    reply_user_data = nullptr;
}

void TestClient::run()
{
    void              *p;
    bool               running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    running = true;
    do {
        int ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, 3000);

        if (ret == -1 && errno != EINTR) {
            GTEST_FATAL_FAILURE_("epoll_wait error");
            break;
        }

        if (ret < 1) {
            ERROR("ret < 1");
            continue;
        }

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            p                     = e.data.ptr;

            if (p == static_cast<AmEventFdQueue *>(this)) {
                processEvents();
            } else if (p == &stop_event) {
                stop_event.read();
                running = false;
                break;
            }
        }

    } while (running);

    DBG("TestClient stopped");
    stopped.set(true);
}

void TestClient::on_stop()
{
    stop_event.fire();
    stopped.wait_for();
}

void TestClient::process(AmEvent *event)
{
    switch (event->event_id) {
    case E_SYSTEM:
    {
        AmSystemEvent *sys_ev = dynamic_cast<AmSystemEvent *>(event);
        if (sys_ev && sys_ev->sys_event == AmSystemEvent::ServerShutdown)
            stop_event.fire();

        return;
    }
    }
}

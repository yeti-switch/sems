#ifndef WORKER_HANDLER_H
#define WORKER_HANDLER_H

#include <sys/epoll.h>
#include <gtest/gtest.h>

#include <AmEventFdQueue.h>
#include <AmEventDispatcher.h>
#include <PostgreSqlAPI.h>

#include "../PostgreSQL.h"

#define WORKER_HANDLER_QUEUE "pg_unit_test"
#define WORKER_POOL_NAME     WORKER_HANDLER_QUEUE
#define EPOLL_MAX_EVENTS    2048

class WorkerHandler : public AmEventFdQueue
                    , public AmEventHandler
{
public:
    int epoll_fd;
    bool running;
    vector<PGEvent::Type> expected_events;

    WorkerHandler()
    : AmEventFdQueue(this)
    , running(true) {
        epoll_fd = epoll_create(10);
        epoll_link(epoll_fd, true);
        
        PGPool pool(POOL_ADDRESS);
        pool.pool_size = 2;
        PostgreSQL::instance()->postEvent(new PGWorkerPoolCreate(WORKER_POOL_NAME, PGWorkerPoolCreate::Master, pool));
        AmEventDispatcher::instance()->addEventQueue(WORKER_HANDLER_QUEUE, this);
    }
    WorkerHandler(const WorkerHandler&) = delete;
    ~WorkerHandler(){
        AmEventDispatcher::instance()->delEventQueue(WORKER_HANDLER_QUEUE);
        epoll_unlink(epoll_fd);
        close(epoll_fd);
    }

    static WorkerHandler& instance() {
        static WorkerHandler handler;
        return handler;
    }
    
    void set_expected_events(const vector<PGEvent::Type>& e) {
        expected_events = e;
    }
    
    void run() {
        void *p;
        struct epoll_event events[EPOLL_MAX_EVENTS];

        running = true;
        do {
            int ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, 2000);

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
                }
            }

        } while(running);
    }
    
    void process(AmEvent* e) override {
        if(expected_events.empty())
            GTEST_FATAL_FAILURE_("expected events is empty");
        GTEST_ASSERT_EQ(e->event_id, expected_events[0]);
        expected_events.erase(expected_events.begin());
        if(expected_events.empty()) running = false;
    }
};

#endif/*WORKER_HANDLER_H*/

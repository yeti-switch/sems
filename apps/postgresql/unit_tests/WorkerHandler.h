#pragma once

#include <sys/epoll.h>
#include <gtest/gtest.h>

#include <AmEventFdQueue.h>
#include <AmEventDispatcher.h>
#include <ampi/PostgreSqlAPI.h>

#include "../PostgreSQL.h"

#define WORKER_HANDLER_QUEUE "pg_unit_test"
#define WORKER_POOL_NAME     WORKER_HANDLER_QUEUE
#define EPOLL_MAX_EVENTS     2048

#define PARAM_PG_ADDR_NAME "address"

#define STR_HELPER(x) #x
#define STR_(x)       STR_HELPER(x)

#define POOL_HOST     "127.0.0.1"
#define POOL_PORT     5434
#define POOL_USER     "yeti"
#define POOL_DATABASE "yeti"
#define POOL_PASS     "yeti"
#define POOL_ADDRESS_STR                                                                                               \
    "host=" POOL_HOST " port=" STR_(POOL_PORT) " user=" POOL_USER " dbname=" POOL_DATABASE " password=" POOL_PASS

PGPool GetPoolByAddress(const string &address);

class WorkerHandler : public AmEventFdQueue, public AmEventHandler {
  private:
    inline static WorkerHandler *_instance = NULL;

  public:
    int                   epoll_fd;
    bool                  running;
    vector<PGEvent::Type> expected_events;

    string address;

    WorkerHandler()
        : AmEventFdQueue(this)
        , running(true)
    {
        epoll_fd = epoll_create(10);
        epoll_link(epoll_fd, true);

        cfg_opt_t postres[] = { CFG_STR(PARAM_PG_ADDR_NAME, POOL_ADDRESS_STR, CFGF_NONE), CFG_END() };
        AmArg     data      = test_config::instance()->configureModule("postgresql_unit", postres);
        address             = data[PARAM_PG_ADDR_NAME].asCStr();
        TesterConfig::ConfigParameters config_parameters;
        config_parameters.emplace<string, TesterConfig::parameter_var>(
            PARAM_PG_ADDR_NAME "-postgres", { .type = TesterConfig::parameter_var::String, .u = { &address } });
        test_config::instance()->useCmdModule(config_parameters);

        PGPool pool    = GetPoolByAddress(address);
        pool.pool_size = 2;
        PostgreSQL::instance()->postEvent(new PGWorkerPoolCreate(WORKER_POOL_NAME, PGWorkerPoolCreate::Master, pool));
        AmEventDispatcher::instance()->addEventQueue(WORKER_HANDLER_QUEUE, this);
    }
    WorkerHandler(const WorkerHandler &) = delete;
    virtual ~WorkerHandler()
    {
        AmEventDispatcher::instance()->delEventQueue(WORKER_HANDLER_QUEUE);
        PostgreSQL::instance()->postEvent(new PGWorkerDestroy(WORKER_POOL_NAME));
        epoll_unlink(epoll_fd);
        close(epoll_fd);
    }

    static WorkerHandler &instance()
    {
        if (_instance == NULL)
            _instance = new WorkerHandler();

        return *_instance;
    }

    static void dispose()
    {
        if (_instance) {
            delete _instance;
            _instance = NULL;
        }
    }

    void set_expected_events(const vector<PGEvent::Type> &e) { expected_events = e; }

    void run()
    {
        void              *p;
        struct epoll_event events[EPOLL_MAX_EVENTS];

        running = true;
        do {
            int ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, 3000);

            if (ret == -1 && errno != EINTR) {
                GTEST_FATAL_FAILURE_("epoll_wait error");
                break;
            }

            if (ret < 1) {
                GTEST_FATAL_FAILURE_("expected event has not got");
                break;
            }

            for (int n = 0; n < ret; ++n) {
                struct epoll_event &e = events[n];
                p                     = e.data.ptr;

                if (p == static_cast<AmEventFdQueue *>(this)) {
                    processEvents();
                }
            }

        } while (running);
        usleep(5000);
    }

    void process(AmEvent *e) override
    {
        if (expected_events.empty())
            GTEST_FATAL_FAILURE_("expected events is empty");
        GTEST_ASSERT_EQ(e->event_id, expected_events[0]);
        expected_events.erase(expected_events.begin());
        if (expected_events.empty())
            running = false;
    }
};

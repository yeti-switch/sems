#ifndef PGHANDLER_H_INCLUDED
#define PGHANDLER_H_INCLUDED

#include "../Connection.h"
#include "../Transaction.h"
#include "../ConnectionPool.h"
#include <log.h>
#include <string.h>
#include <sys/epoll.h>
#include <gtest/gtest.h>
#include <../unit_tests/Config.h>

#define STR_HELPER(x) #x
#define STR_(x) STR_HELPER(x)

#define POOL_HOST           "127.0.0.1"
#define POOL_PORT           5434
#define POOL_USER           "yeti"
#define POOL_DATABASE       "yeti"
#define POOL_PASS           "yeti"
#define POOL_ADDRESS        POOL_HOST, POOL_PORT, POOL_DATABASE, POOL_USER, POOL_PASS
#define POOL_ADDRESS_STR    "host=" POOL_HOST " port=" STR_(POOL_PORT) " user=" POOL_USER " dbname=" POOL_DATABASE " password=" POOL_PASS

class PostgresqlTest : public ::testing::Test
{
protected:
    TestServer server;
    void SetUp() override
    {
        PolicyFactory::dispose();
        makePolicyFactory(!test_config::instance()->external_postgres, &server);
        server.clear();
    }
};

class PGHandler : public IConnectionHandler
                , public ITransactionHandler
{
public:
    int epoll_fd;
    enum State {
        CONNECTED,
        DISCONNECTED,
        FINISH
    } cur_state;
    int dis_count;
    int count;
    vector<Worker*> workers;
    vector<IPGConnection*> reset;

    PGHandler()
    : cur_state(DISCONNECTED)
    , dis_count(0), count(0)
    {
        epoll_fd = epoll_create(10);
    }
    ~PGHandler()
    {
        close(epoll_fd);
    }

    int check() {

        if(dis_count > 10) {
            []() {
                GTEST_FATAL_FAILURE_("can't connect to server");
            }();
            return 0;
        }

        auto reset_conns = reset;
        reset.clear();
        for(auto conn : reset_conns)
            conn->reset();
        if(!reset_conns.empty()) {
            return 1;
        }

        struct epoll_event events[2046];
        int ret = epoll_wait(epoll_fd, events, 2046, 10000);
        if(ret == -1 && errno != EINTR){
            ERROR("epoll_wait: %s",strerror(errno));
            return -1;
        }

        if(ret < 1) {
            []() {
                GTEST_FATAL_FAILURE_("expected event has not got");
            }();
            return 0;
        }

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            void* p = e.data.ptr;
            bool is_connection = true;
            for(auto& worker : workers) {
                if(worker->processEvent(p)) {
                    is_connection = false;
                    break;
                }
            }
            if(is_connection) {
                IPGConnection* conn = (IPGConnection*)e.data.ptr;
                conn->check();
            }
        }
        return 1;
    }
protected:
    void onConnect(IPGConnection*) override
    {
        INFO("connected");
        cur_state = CONNECTED;
        count++;
    }

    void onDisconnect(IPGConnection* conn) override
    {
        INFO("disconnected");
        cur_state = DISCONNECTED;
        dis_count++;
        reset.push_back(conn);
    }

    void onReset(IPGConnection*) override
    {
        INFO("reset");
        cur_state = DISCONNECTED;
        dis_count++;
    }

    void onConnectionFailed(IPGConnection* conn, const string& error) override
    {
        ERROR("connection failed, error: %s", error.c_str());
        reset.push_back(conn);
    }

    void onStopTransaction(IPGTransaction* trans) override
    {
        INFO("stopped transaction %s", trans->get_query()->get_query().c_str());
    }

    void onSock(IPGConnection* conn, EventType type) override
    {
        if(type == PG_SOCK_NEW) {
            epoll_event event;
            event.events = EPOLLIN | EPOLLERR | EPOLLET;
            event.data.ptr = conn;

            // add the socket to the epoll file descriptors
            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn->getSocket(), &event);
        } else if(type == PG_SOCK_DEL) {
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->getSocket(), nullptr);
        } else {
            epoll_event event;
            event.events = EPOLLERR;
            event.data.ptr = conn;
            if(type == PG_SOCK_WRITE) event.events |= EPOLLOUT;
            if(type == PG_SOCK_READ) event.events |= EPOLLIN;

            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->getSocket(), &event);
        }
    }

    void onCancel(IPGTransaction*) override
    {
        INFO("exec cancel");
    }

    void onError(IPGTransaction*, const string& error) override
    {
        ERROR("exec query error: %s", error.c_str());
    }

    void onPQError(IPGConnection*, const std::string & error) override
    {
        ERROR("pq error: %s", error.c_str());
    }
    
    void onPQError(IPGTransaction*, const std::string & error) override
    {
        ERROR("pq error: %s", error.c_str());
    }

    void onFinish(IPGTransaction*, const AmArg & result) override
    {
        cur_state = FINISH;
        INFO("exec finish: %s", AmArg::print(result).c_str());
    }

    void onTuple(IPGTransaction*, const AmArg & result) override
    {
        INFO("exec tuple result: %s", AmArg::print(result).c_str());
    }
};


#endif // PGHANDLER_H_INCLUDED

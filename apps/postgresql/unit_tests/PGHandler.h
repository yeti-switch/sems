#pragma once

#include "../conn/Connection.h"
#include "../trans/Transaction.h"
#include "../ConnectionPool.h"
#include "../PoolWorker.h"
#include <log.h>
#include <string.h>
#include <sys/epoll.h>
#include <gtest/gtest.h>
#include <../unit_tests/Config.h>
#include "WorkerHandler.h"

class PostgresqlTest : public ::testing::Test
{
public:
    TestServer* server;
    bool external;
    string address;
    PostgresqlTest() {
        address = WorkerHandler::instance().address;
        server = &WorkerHandler::instance().server;
        external = WorkerHandler::instance().external;
    }
    void SetUp() override
    {
        server->clear();
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
    vector<PoolWorker*> workers;
    vector<Connection*> reset;

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
                    //DBG("worker event");
                    is_connection = false;
                    break;
                }
            }
            if(is_connection) {
                //DBG("connection event");
                Connection* conn = (Connection*)e.data.ptr;
                conn->check();
            }
        }
        for(auto& worker : workers)
            worker->applyTimer();
        return 1;
    }
protected:
    void onConnect(Connection*) override
    {
        INFO("connected");
        cur_state = CONNECTED;
        count++;
    }

    void onDisconnect(Connection* conn) override
    {
        INFO("disconnected");
        cur_state = DISCONNECTED;
        dis_count++;
        reset.push_back(conn);
    }

    void onReset(Connection*, bool connected) override
    {
        INFO("reset");
        cur_state = DISCONNECTED;
        dis_count++;
    }

    void onConnectionFailed(Connection* conn, const string& error) override
    {
        ERROR("connection failed, error: %s", error.c_str());
        reset.push_back(conn);
    }

    void onStopTransaction(Transaction* trans) override
    {
        INFO("stopped transaction %s", trans->get_query()->get_query().c_str());
    }

    void onSock(Connection* conn, EventType type) override
    {
        int conn_fd = conn->getSocket();
        if(conn_fd < 0) return;

        //DBG("type posgres sock event %u", type);
        if(type == PG_SOCK_NEW) {
            epoll_event event;
            event.events = EPOLLIN | EPOLLERR | EPOLLET;
            event.data.ptr = conn;

            // add the socket to the epoll file descriptors
            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_fd, &event);
        } else if(type == PG_SOCK_DEL) {
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn_fd, nullptr);
        } else {
            epoll_event event;
            event.events = EPOLLERR;
            event.data.ptr = conn;

            if(type == PG_SOCK_READ) event.events |= EPOLLIN;
            if(type == PG_SOCK_WRITE) event.events |= EPOLLOUT;
            if(type == PG_SOCK_RW) event.events |= EPOLLIN | EPOLLOUT;

            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn_fd, &event);
        }
    }

    void onCancel(Transaction*) override
    {
        INFO("exec cancel");
    }

    void onSend(Transaction *) override{}

    void onError(Transaction* trans, const string& error) override
    {
        ERROR("exec query '%s' error: %s", trans->get_query()->get_query().c_str(), error.c_str());
    }

    void onErrorCode(Transaction* , const string& error) override
    {
        ERROR("error code: %s", error.c_str());
    }

    void onPQError(Connection*, const std::string & error) override
    {
        ERROR("pq error: %s", error.c_str());
    }
    
    void onPQError(Transaction*, const std::string & error) override
    {
        ERROR("pq error: %s", error.c_str());
    }

    void onFinish(Transaction* trans, const AmArg & result) override
    {
        cur_state = FINISH;
        INFO("exec finish: %s", AmArg::print(result).c_str());
    }

    void onTuple(Transaction*, const AmArg & result) override
    {
        INFO("exec tuple result: %s", AmArg::print(result).c_str());
    }
};

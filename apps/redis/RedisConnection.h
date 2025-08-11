#pragma once

#include <AmThread.h>
#include <AmEventFdQueue.h>
#include <AmSessionContainer.h>
#include <AmArg.h>

#include "RedisInstance.h"

#include <memory>
#include <cmath>
#include "./unit_tests/RedisTest.h"

template <typename T> inline unsigned int len_in_chars(T s)
{
    if (s == 0)
        return 1;
    return static_cast<unsigned int>(log10(s) + 1);
}

class RedisConnection;

class RedisConnectionStateListener {
  protected:
    friend RedisConnection;
    virtual void on_connect(RedisConnection *c) {};
    virtual void on_disconnect(RedisConnection *c) {};
};

class RedisConnection {
  private:
    friend RedisTest;
    int epoll_fd;

    string host;
    int    port;

    redisAsyncContext *async_context;
    AmCondition<bool>  connected;
    AmCondition<bool>  master;
    int                mask;

    bool                          needAutorization;
    string                        username;
    string                        password;
    string                        name;
    RedisConnectionStateListener *state_listener;

  protected:
    void on_connect();
    void on_disconnect();

    void detect_role();

  public:
    RedisConnection(const char *name, RedisConnectionStateListener *state_listener);
    virtual ~RedisConnection();
    int  init(int epoll_fd, const string &host, int port);
    void set_auth_data(const string &password, const string &username = "");
    void connect();
    int  reconnect(const string &host, int port);

    redisAsyncContext *get_async_context() { return async_context; }
    void               cleanup();
    bool               is_connected() { return connected.get(); }
    bool               is_master() { return master.get(); }
    const char        *get_name() { return name.c_str(); }
    const string      &get_host() const { return host; }
    int                get_port() const { return port; }

    // for unit_tests
    bool wait_connected() { return connected.wait_for_to(500); }

    redisConnectCallback    connectCallback;
    redisDisconnectCallback disconnectCallback;
    redisCallbackFn         authCallback;
    redisCallbackFn         roleCallback;

    int add_event(int flag);
    int del_event(int flag);
};

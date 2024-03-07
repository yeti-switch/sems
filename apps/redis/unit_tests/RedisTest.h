#pragma once

#include <singleton.h>
#include <gtest/gtest.h>
#include "RedisTestServer.h"

#include <string>
using std::string;

#define DEFAULT_REDIS_TIMEOUT_MSEC 1000

class RedisTest : public testing::Test
{
protected:
    RedisTestServer* test_server;
public:
    RedisTest();

    void SetUp() override;
};

struct RedisSettings{
    bool external;
    string host;
    int port;
    int timeout;
    RedisSettings()
      : timeout(DEFAULT_REDIS_TIMEOUT_MSEC)
    {}
};

struct RedisTestFactory
{
    RedisTestServer test_server;
    RedisSettings settings;
    RedisTestFactory();
    void read_config();
};

typedef singleton<RedisTestFactory> redis_test;

#pragma once

#include <singleton.h>
#include <gtest/gtest.h>

#include <string>
using std::string;

#define DEFAULT_REDIS_TIMEOUT_MSEC 1000

class RedisTest : public testing::Test {};

struct RedisSettings {
    string host;
    int    port;
    int    timeout;
    RedisSettings()
        : timeout(DEFAULT_REDIS_TIMEOUT_MSEC)
    {
    }
};

struct RedisTestFactory {
    RedisSettings settings;
    RedisTestFactory();
    void read_config();
};

typedef singleton<RedisTestFactory> redis_test;

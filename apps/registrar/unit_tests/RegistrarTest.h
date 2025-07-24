#pragma once

#include "../RegistrarRedisClient.h"

#include <apps/redis/unit_tests/RedisTest.h>
#include <singleton.h>

#include <gtest/gtest.h>
#include <string>

using std::string;

#define DEFAULT_REDIS_TIMEOUT_MSEC 1000

const char register_script_hash[] = "5f43acad4661a5abf51ab3f32fdf2d1b1a9fec65";
const char aor_lookup_script_hash[] = "af857bc30e9cd6e67f316dc9b0910a19f939f84e";
const char rpc_aor_lookup_script_hash[] = "91d6959f211b09a6e7b0f1c3c9fd5bf717a371c9";
const char load_contacts_script_hash[] = "a74bd2c0d28faea0cba58a939af200414ad87ef0";
const char interface_name[] = "input";

class RegistrarTest : public testing::Test
{
protected:
    RedisSettings settings;
    RedisTestServer* test_server;
    typedef RegistrarRedisClient::Connection::State ConnState;

public:
    RegistrarTest();

    void SetUp() override;

    void dumpKeepAliveContexts(AmArg& ret);
    void clear_keepalive_context();
};

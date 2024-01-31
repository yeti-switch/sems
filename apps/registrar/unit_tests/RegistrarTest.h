#pragma once

#include <singleton.h>
#include <gtest/gtest.h>
#include "RedisTestServer.h"

#define DEFAULT_REDIS_TIMEOUT_MSEC 1000

const char register_script_hash[] = "5f43acad4661a5abf51ab3f32fdf2d1b1a9fec65";
const char aor_lookup_script_hash[] = "af857bc30e9cd6e67f316dc9b0910a19f939f84e";
const char rpc_aor_lookup_script_hash[] = "91d6959f211b09a6e7b0f1c3c9fd5bf717a371c9";
const char load_contacts_script_hash[] = "a74bd2c0d28faea0cba58a939af200414ad87ef0";

const char register_script_path[] = "/etc/sems/scripts/register.lua";
const char aor_lookup_script_path[] = "/etc/sems/scripts/aor_lookup.lua";
const char rpc_aor_lookup_script_path[] = "/etc/sems/scripts/rpc_aor_lookup.lua";
const char load_contacts_script_path[] = "/etc/sems/scripts/load_contacts.lua";

class ContactsSubscriptionConnection;
class RegistrarRedisConnection;

class RegistrarTest : public testing::Test
{
protected:
    RedisTestServer* server;
public:
    RegistrarTest();

    void SetUp() override;

    ContactsSubscriptionConnection* get_contacts_subscription();
    RegistrarRedisConnection* get_registrar_redis();
    void clear_keepalive_context();
};

struct RegistrarTestFactory
{
    RedisTestServer server;
    struct RedisSettings{
        bool external;
        string host;
        int port;
        int timeout;
        RedisSettings()
          : timeout(DEFAULT_REDIS_TIMEOUT_MSEC)
        {}
    } redis;

    RegistrarTestFactory();
    ~RegistrarTestFactory();

    void dispose(){}
};

typedef singleton<RegistrarTestFactory> registrar_test;

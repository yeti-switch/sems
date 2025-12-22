#pragma once

#include "../RegistrarRedisClient.h"

#include <apps/redis/unit_tests/RedisTest.h>
#include <singleton.h>

#include <gtest/gtest.h>
#include <string>

using std::string;

class RegistrarTest : public testing::Test {
  protected:
    RedisSettings                                   settings;
    typedef RegistrarRedisClient::Connection::State ConnState;

  public:
    RegistrarTest();

    void SetUp() override;

    void dumpKeepAliveContexts(AmArg &ret);
    void clear_keepalive_context();
};

class RegistrarTestFactory : public Configurable {
    string scripts_dir;
    string get_script_path(const string &sript_name);

  public:
    RegistrarTestFactory();
    int configure(cfg_t *cfg) override;
};

typedef singleton<RegistrarTestFactory> registrar_test;

#include "RedisTest.h"
#include "../RedisInstance.h"
#include "../RedisApp.h"
#include "unit_tests/Config.h"

#include <hiredis/read.h>
#include <confuse.h>

#define PARAM_REDIS_HOST_NAME "host"
#define PARAM_REDIS_PORT_NAME "port"
#define SECTION_REDIS_NAME    "redis"

#define STR_HELPER(x) #x
#define STR_(x)       STR_HELPER(x)

#define HOST "127.0.0.1"
#define PORT 6379

static redis_test *redis_global = redis_test::instance();

/* RedisTestFactory */

RedisTestFactory::RedisTestFactory()
{
    read_config();
}

void RedisTestFactory::read_config()
{
    cfg_opt_t opts[] = { CFG_STR(PARAM_REDIS_HOST_NAME, HOST, CFGF_NONE),
                         CFG_INT(PARAM_REDIS_PORT_NAME, PORT, CFGF_NONE), CFG_END() };

    AmArg data    = test_config::instance()->configureModule("redis_unit", opts);
    settings.host = data[PARAM_REDIS_HOST_NAME].asCStr();
    settings.port = data[PARAM_REDIS_PORT_NAME].asLong();
    TesterConfig::ConfigParameters config_parameters;
    config_parameters.emplace<string, TesterConfig::parameter_var>(
        SECTION_REDIS_NAME "-" PARAM_REDIS_HOST_NAME,
        { .type = TesterConfig::parameter_var::String, .u = { &settings.host } });
    config_parameters.emplace<string, TesterConfig::parameter_var>(
        SECTION_REDIS_NAME "-" PARAM_REDIS_PORT_NAME,
        { .type = TesterConfig::parameter_var::Integer, .u = { &settings.port } });
    test_config::instance()->useCmdModule(config_parameters);
}

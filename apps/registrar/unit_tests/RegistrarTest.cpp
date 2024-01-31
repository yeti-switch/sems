#include "RegistrarTest.h"
#include "../RedisInstance.h"
#include "../../unit_tests/Config.h"
#include "../SipRegistrar.h"

#include <hiredis/read.h>

#include <confuse.h>


#define PARAM_EXT_REDIS_NAME     "external"
#define PARAM_REDIS_HOST_NAME    "host"
#define PARAM_REDIS_PORT_NAME    "port"
#define SECTION_REDIS_NAME       "redis"

#define STR_HELPER(x) #x
#define STR_(x) STR_HELPER(x)

#define HOST           "127.0.0.1"
#define PORT           6379

static registrar_test* registrar_global = registrar_test::instance();

int add_responses_for_all_load_script_commands();

RegistrarTest::RegistrarTest() {
    DBG("RegistrarTest");
    server = &registrar_global->server;
}

void RegistrarTest::SetUp() {
    DBG("RegistrarTest SetUp");
    server->clear();
}

ContactsSubscriptionConnection* RegistrarTest::get_contacts_subscription()
{
    return &SipRegistrar::instance()->contacts_subscription;
}

RegistrarRedisConnection* RegistrarTest::get_registrar_redis()
{
    return &SipRegistrar::instance()->registrar_redis;
}

void RegistrarTest::clear_keepalive_context()
{
    get_contacts_subscription()->clearKeepAliveContexts();
}

class RegistrarTestListener : public testing::EmptyTestEventListener
{
public:
    void OnTestProgramStart(const testing::UnitTest&) override
    {
        add_responses_for_all_load_script_commands();
        SipRegistrar::instance()->reload();

        for(int r = 0; SipRegistrar::instance()->is_loaded() == false && r < 10; ++r) {
            DBG("waiting for SipRegistrar loading");
            usleep(500);
        }

        cfg_opt_t redis[] = {
            CFG_BOOL(PARAM_EXT_REDIS_NAME, cfg_false, CFGF_NONE),
            CFG_STR(PARAM_REDIS_HOST_NAME, HOST, CFGF_NONE),
            CFG_INT(PARAM_REDIS_PORT_NAME, PORT, CFGF_NONE),
            CFG_END()
        };
        cfg_opt_t opts[] = {
            CFG_SEC(SECTION_REDIS_NAME, redis, CFGF_NONE),
            CFG_END()
        };

        AmArg data = test_config::instance()->configureModule("registrar", opts);
        RegistrarTestFactory::RedisSettings& redis_setting = registrar_global->redis;
        redis_setting.external = data[SECTION_REDIS_NAME][PARAM_EXT_REDIS_NAME].asBool();
        redis_setting.host = data[SECTION_REDIS_NAME][PARAM_REDIS_HOST_NAME].asCStr();
        redis_setting.port = data[SECTION_REDIS_NAME][PARAM_REDIS_PORT_NAME].asLong();
        TesterConfig::ConfigParameters config_parameters;
        config_parameters.emplace<string, TesterConfig::parameter_var>(PARAM_EXT_REDIS_NAME "-" SECTION_REDIS_NAME, {.type = TesterConfig::parameter_var::Bool, .u = {&redis_setting.external}});
        config_parameters.emplace<string, TesterConfig::parameter_var>(SECTION_REDIS_NAME "-" PARAM_REDIS_HOST_NAME, {.type = TesterConfig::parameter_var::String, .u = {&redis_setting.host}});
        config_parameters.emplace<string, TesterConfig::parameter_var>(SECTION_REDIS_NAME "-" PARAM_REDIS_PORT_NAME, {.type = TesterConfig::parameter_var::Integer, .u = {&redis_setting.port}});
        test_config::instance()->useCmdModule(config_parameters);
    }

    void OnTestProgramEnd(const testing::UnitTest&) override
    {
        registrar_test::dispose();
    }
};

RegistrarTestFactory::RegistrarTestFactory()
{
    makeRedisInstance(true, &server);
    testing::UnitTest::GetInstance()->listeners().Append(new RegistrarTestListener);
}

RegistrarTestFactory::~RegistrarTestFactory()
{
    freeRedisInstance();
}

int add_responses_for_all_load_script_commands()
{
    map<string, string> scripts;
    scripts[register_script_hash] = register_script_path;
    scripts[aor_lookup_script_hash] = aor_lookup_script_path;
    scripts[rpc_aor_lookup_script_hash] = rpc_aor_lookup_script_path;
    scripts[load_contacts_script_hash] = load_contacts_script_path;

    for(auto script : scripts) {
        string data;
        if(RedisScript::get_script_data(script.second, data) < 0)
            continue;

        AmArg ret = script.first;
        registrar_test::instance()->server.addCommandResponse("SCRIPT LOAD %s",
            REDIS_REPLY_STRING, ret, data.c_str());
    }

    return 0;
}

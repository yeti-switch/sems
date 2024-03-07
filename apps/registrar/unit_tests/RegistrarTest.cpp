#include "RegistrarTest.h"
#include "../SipRegistrar.h"

class RegistrarTestInitialiser
{
protected:
    RedisSettings settings;
    RedisTestServer* test_server;

    void initTestServer()
    {
        test_server->response_enabled.set(false);
        test_server->addLoadScriptCommandResponse(register_script_path, register_script_hash);
        test_server->addLoadScriptCommandResponse(aor_lookup_script_path, aor_lookup_script_hash);
        test_server->addLoadScriptCommandResponse(rpc_aor_lookup_script_path, rpc_aor_lookup_script_hash);
        test_server->addLoadScriptCommandResponse(load_contacts_script_path, load_contacts_script_hash);
        test_server->response_enabled.set(true);
    }
public:
    RegistrarTestInitialiser()
    {
        DBG("RegistrarTestInitialiser");
        test_server = &redis_test::instance()->test_server;
        settings = redis_test::instance()->settings;
        initTestServer();
    }
};
typedef singleton<RegistrarTestInitialiser> registrar_init;
static registrar_init* registrar_global = registrar_init::instance();

RegistrarTest::RegistrarTest() {
    DBG("RegistrarTest");
    test_server = &redis_test::instance()->test_server;
    settings = redis_test::instance()->settings;
}

void RegistrarTest::SetUp() {
    DBG("RegistrarTest SetUp");

    test_server->response_enabled.set(false);
    test_server->clear();
    test_server->addLoadScriptCommandResponse(register_script_path, register_script_hash);
    test_server->addLoadScriptCommandResponse(aor_lookup_script_path, aor_lookup_script_hash);
    test_server->addLoadScriptCommandResponse(rpc_aor_lookup_script_path, rpc_aor_lookup_script_hash);
    test_server->addLoadScriptCommandResponse(load_contacts_script_path, load_contacts_script_hash);
    test_server->response_enabled.set(true);
}

void RegistrarTest::dumpKeepAliveContexts(AmArg& ret)
{
    SipRegistrar::instance()->dump_keep_alive_contexts(ret);
}

void RegistrarTest::clear_keepalive_context()
{
    SipRegistrar::instance()->clear_keep_alive_contexts();
}

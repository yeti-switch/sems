#include "RegistrarTest.h"
#include "../SipRegistrar.h"
#include <hiredis/read.h>

#define registrar SipRegistrar::instance()

RegistrarTest::RegistrarTest() {
    DBG("RegistrarTest");
    test_server = &redis_test::instance()->test_server;
    settings = redis_test::instance()->settings;
}

void RegistrarTest::SetUp() {
    DBG("RegistrarTest SetUp");

    test_server->response_enabled.set(false);
    test_server->clear();
    AmArg master;
    master.push("master");
    test_server->addCommandResponse("ROLE", REDIS_REPLY_ARRAY, master);
    test_server->addLoadScriptCommandResponse(registrar->get_script_path(REGISTER_SCRIPT), register_script_hash);
    test_server->addLoadScriptCommandResponse(registrar->get_script_path(AOR_LOOKUP_SCRIPT), aor_lookup_script_hash);
    test_server->addLoadScriptCommandResponse(registrar->get_script_path(RPC_AOR_LOOKUP_SCRIPT), rpc_aor_lookup_script_hash);
    test_server->addLoadScriptCommandResponse(registrar->get_script_path(LOAD_CONTACTS_SCRIPT), load_contacts_script_hash);
    test_server->response_enabled.set(true);

    auto isConnExists = [&](ConnState state)
    {
        for(auto & conn : registrar->connections)
            if(conn->state == state) return true;

        return false;
    };

    /*
     * registrar tries to connect all connections on SipRegistrar::run();
     * if we are using test server 'SCRIPT LOAD' cached answer can be absent;
     * that's why some of connections can be disconnected at this point;
     * connection is considered as 'Connected' only when it connected to db
     * and all connection's scripts are loaded to db;
     * wait for 'Connected' or 'Disconnected' states;
     *
     */

    time_t time_ = time(0);
    while(isConnExists(ConnState::None)) {
        //DBG("waiting for connections states");
        usleep(100);
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    // check is need to reconnect
    if(isConnExists(ConnState::Disconnected))
        registrar->connect_all();

    time_ = time(0);
    while(isConnExists(ConnState::Disconnected)) {
        //DBG("waiting for all connections in 'Connected' state");
        usleep(100);
        ASSERT_FALSE(time(0) - time_ > 3);
    }
}

void RegistrarTest::dumpKeepAliveContexts(AmArg& ret)
{
    registrar->dump_keep_alive_contexts(ret);
}

void RegistrarTest::clear_keepalive_context()
{
    registrar->clear_keep_alive_contexts();
}

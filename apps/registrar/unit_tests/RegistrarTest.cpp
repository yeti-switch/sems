#include "RegistrarTest.h"
#include "../SipRegistrar.h"
#include "format_helper.h"

#include <hiredis/read.h>

#define registrar SipRegistrar::instance()

RegistrarTestFactory *registrar_test_global = registrar_test::instance();

RegistrarTestFactory::RegistrarTestFactory()
{
    reg_config::instance()->addConfObject(this);
}

string RegistrarTestFactory::get_script_path(const string &sript_name)
{
    return format("{}/{}.lua", scripts_dir, sript_name);
}

int RegistrarTestFactory::configure(cfg_t *cfg)
{
    auto reg_redis = cfg_getsec(cfg, CFG_SEC_REDIS);
    if (!reg_redis)
        return -1;

    scripts_dir = cfg_getstr(reg_redis, CFG_PARAM_SCRIPTS_DIR);
    return 0;
}

RegistrarTest::RegistrarTest()
{
    DBG("RegistrarTest");
    settings = redis_test::instance()->settings;
}

void RegistrarTest::SetUp()
{
    DBG("RegistrarTest SetUp");

    auto isConnExists = [&](ConnState state) {
        for (auto &conn : registrar->connections)
            if (conn->state == state)
                return true;

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
    while (isConnExists(ConnState::None)) {
        // DBG("waiting for connections states");
        usleep(100);
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    // check is need to reconnect
    if (isConnExists(ConnState::Disconnected))
        registrar->connect_all();

    time_ = time(0);
    while (isConnExists(ConnState::Disconnected)) {
        // DBG("waiting for all connections in 'Connected' state");
        usleep(100);
        ASSERT_FALSE(time(0) - time_ > 3);
    }
}

void RegistrarTest::dumpKeepAliveContexts(AmArg &ret)
{
    registrar->dump_keep_alive_contexts(ret);
}

void RegistrarTest::clear_keepalive_context()
{
    registrar->clear_keep_alive_contexts();
}

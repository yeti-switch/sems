#include "RegistrarRedisClient.h"
#include <AmPlugIn.h>

/* Connection */

RegistrarRedisClient::Connection::Connection(const string &id)
  : id(id), info(), is_connected()
{
    DBG("RegistrarRedisClient::Connection::Connection(..)");
}

RegistrarRedisClient::Connection::~Connection()
{
    DBG("RegistrarRedisClient::Connection::~Connection()");
}

const RedisScript* RegistrarRedisClient::Connection::script(const string &name) {
    for(const auto & s : info.scripts)
        if(s.name == name)
            return &s;

    return nullptr;
}

/* RegistrarRedisClient */

RegistrarRedisClient::RegistrarRedisClient()
{
    read_conn = new Connection(REG_READ_CONN_ID);
    subscr_read_conn = new Connection(REG_SUBSCR_READ_CONN_ID);
    write_conn = new Connection(REG_WRITE_CONN_ID);

    connections.emplace_back(read_conn);
    connections.emplace_back(subscr_read_conn);
    connections.emplace_back(write_conn);
}

int RegistrarRedisClient::configure(cfg_t* cfg)
{
    auto reg_redis = cfg_getsec(cfg, CFG_SEC_REDIS);
    if(!reg_redis)
        return -1;

    use_functions = cfg_getbool(reg_redis, CFG_PARAM_USE_FUNCTIONS);
    auto reg_redis_write = cfg_getsec(reg_redis, CFG_SEC_WRITE);
    auto reg_redis_read = cfg_getsec(reg_redis, CFG_SEC_READ);
    if(!reg_redis_read || !reg_redis_write)
        return -1;

    auto cfg_conn_info = [](cfg_t* cfg, RedisConnectionInfo &info) {
        info.host = cfg_getstr(cfg, CFG_PARAM_HOST);
        info.port = cfg_getint(cfg, CFG_PARAM_PORT);

        if(cfg_size(cfg, CFG_PARAM_PASSWORD)) {
            info.password = cfg_getstr(cfg, CFG_PARAM_PASSWORD);
            if(cfg_size(cfg, CFG_PARAM_USERNAME))
                info.username = cfg_getstr(cfg, CFG_PARAM_USERNAME);
        }
    };

    cfg_conn_info(reg_redis_read, read_conn->info);
    cfg_conn_info(reg_redis_read, subscr_read_conn->info);
    cfg_conn_info(reg_redis_write, write_conn->info);

    read_conn->info.scripts = {
        {AOR_LOOKUP_SCRIPT, "/etc/sems/scripts/aor_lookup.lua"},
        {RPC_AOR_LOOKUP_SCRIPT, "/etc/sems/scripts/rpc_aor_lookup.lua"}
    };
    subscr_read_conn->info.scripts = {{LOAD_CONTACTS_SCRIPT, "/etc/sems/scripts/load_contacts.lua"}};
    write_conn->info.scripts = {{REGISTER_SCRIPT, "/etc/sems/scripts/register.lua"}};

    // check dependencies
    if(!AmPlugIn::instance()->getFactory4Config("redis")) {
        ERROR("redis module isn't loaded");
        return -1;
    }

    return 0;
}

void RegistrarRedisClient::connect_all()
{
    for(const auto & conn : connections)
        connect(*conn);
}

void RegistrarRedisClient::on_connect(const string &conn_id, const RedisConnectionInfo &info)
{
    for(auto & conn : connections)
        if(conn->id == conn_id) {
            conn->is_connected = true;
            conn->info = info;
            break;
        }
}

void RegistrarRedisClient::on_disconnect(const string &conn_id, const RedisConnectionInfo &info)
{
    for(auto & conn : connections)
        if(conn->id == conn_id) {
            conn->is_connected = false;
            conn->info = info;
            break;
        }
}

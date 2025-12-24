#include "RegistrarRedisClient.h"
#include <AmPlugIn.h>
#include "AmUtils.h"
#include <format_helper.h>

/* Connection */

RegistrarRedisClient::Connection::Connection(const string &id)
    : id(id)
    , info()
    , state(None)
{
    DBG3("RegistrarRedisClient::Connection::Connection(..)");
}

RegistrarRedisClient::Connection::~Connection()
{
    DBG3("RegistrarRedisClient::Connection::~Connection()");
}

const RedisScript *RegistrarRedisClient::Connection::script(const string &name)
{
    for (const auto &s : info.scripts)
        if (s.name == name)
            return &s;

    return nullptr;
}

/* RegistrarRedisClient */

RegistrarRedisClient::RegistrarRedisClient()
{
    read_conn        = new Connection(REG_READ_CONN_ID);
    subscr_read_conn = new Connection(REG_SUBSCR_READ_CONN_ID);
    write_conn       = new Connection(REG_WRITE_CONN_ID);

    connections.emplace_back(read_conn);
    connections.emplace_back(subscr_read_conn);
    connections.emplace_back(write_conn);
}

inline void fill_info_addrs(cfg_t *cfg, RedisConnectionInfo &info)
{
    for (unsigned int i = 0; i < cfg_size(cfg, CFG_PARAM_HOSTS); i++) {
        auto host_port = parse_hostport(cfg_getnstr(cfg, CFG_PARAM_HOSTS, i), true);
        if (host_port.has_value())
            info.addrs.emplace_back(host_port.value().first, host_port.value().second);
    }
}

int RegistrarRedisClient::configure(cfg_t *cfg)
{
    auto reg_redis = cfg_getsec(cfg, CFG_SEC_REDIS);
    if (!reg_redis)
        return -1;

    scripts_dir          = cfg_getstr(reg_redis, CFG_PARAM_SCRIPTS_DIR);
    auto reg_redis_write = cfg_getsec(reg_redis, CFG_SEC_WRITE);
    auto reg_redis_read  = cfg_getsec(reg_redis, CFG_SEC_READ);
    if (!reg_redis_read || !reg_redis_write)
        return -1;

    auto cfg_conn_info = [&reg_redis_read, &reg_redis_write](cfg_t *cfg, RedisConnectionInfo &info) -> int {
        if (reg_redis_read == cfg) {
            info.role = RedisSlave;
            fill_info_addrs(cfg, info);
            if (info.addrs.empty()) {
                ERROR("absent redis read connections");
                return -1;
            }
        }

        if (reg_redis_write == cfg) {
            info.role = RedisMaster;
            fill_info_addrs(cfg, info);
            if (info.addrs.empty()) {
                ERROR("absent redis write connections");
                return -1;
            }
        }

        if (cfg_size(cfg, CFG_PARAM_PASSWORD)) {
            info.password = cfg_getstr(cfg, CFG_PARAM_PASSWORD);
            if (cfg_size(cfg, CFG_PARAM_USERNAME))
                info.username = cfg_getstr(cfg, CFG_PARAM_USERNAME);
        }

        return 0;
    };

    if (cfg_conn_info(reg_redis_read, read_conn->info) || cfg_conn_info(reg_redis_read, subscr_read_conn->info) ||
        cfg_conn_info(reg_redis_write, write_conn->info))
    {
        return -1;
    }

    read_conn->info.scripts = {
        {     AOR_LOOKUP_SCRIPT,     get_script_path(AOR_LOOKUP_SCRIPT) },
        { RPC_AOR_LOOKUP_SCRIPT, get_script_path(RPC_AOR_LOOKUP_SCRIPT) }
    };
    subscr_read_conn->info.scripts = {
        { LOAD_CONTACTS_SCRIPT, get_script_path(LOAD_CONTACTS_SCRIPT) }
    };
    write_conn->info.scripts = {
        {           REGISTER_SCRIPT,           get_script_path(REGISTER_SCRIPT) },
        { RPC_TRANSPORT_DOWN_SCRIPT, get_script_path(RPC_TRANSPORT_DOWN_SCRIPT) }
    };

    // check dependencies
    if (!AmPlugIn::instance()->getFactory4Config("redis")) {
        ERROR("redis module isn't loaded");
        return -1;
    }

    return 0;
}

string RegistrarRedisClient::get_script_path(const string &sript_name)
{
    return format("{}/{}.lua", scripts_dir, sript_name);
}

void RegistrarRedisClient::connect_all()
{
    for (const auto &conn : connections)
        connect(*conn);
}

void RegistrarRedisClient::on_connect(const string &conn_id, const RedisConnectionInfo &info)
{
    for (auto &conn : connections)
        if (conn->id == conn_id) {
            conn->state = Connection::Connected;
            conn->info  = info;
            break;
        }
}

void RegistrarRedisClient::on_disconnect(const string &conn_id, const RedisConnectionInfo &info)
{
    for (auto &conn : connections)
        if (conn->id == conn_id) {
            conn->state = Connection::Disconnected;
            conn->info  = info;
            break;
        }
}

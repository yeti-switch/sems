#include "SipRegistrarConfig.h"
#include <log.h>
#include <AmUtils.h>

vector<RedisAddr> redis_write_addrs;
vector<RedisAddr> redis_read_addrs;

int redis_connection_func(cfg_t *cfg, cfg_opt_t */*opt*/, int argc, const char **argv)
{
    if(argc != 2) {
        ERROR("header(): unexpected option args count %d, "
              "expected format: connection(host, port)", argc);
        return -1;
    }

    string host = argv[0];
    int port =  0;
    if(!str2int(argv[1], port)) {
        ERROR("incorrect second parameter in redis connection option(port): must be int");
        return -1;
    }

    if(strcmp(cfg->name, CFG_SEC_WRITE) == 0)
        redis_write_addrs.emplace_back(host, port);
    else if(strcmp(cfg->name, CFG_SEC_READ) == 0)
        redis_read_addrs.emplace_back(host, port);
    return 0;
}

int SipRegistrarConfig::parse(const string& config, Configurable* obj)
{
    cfg_opt_t redis_pool_opts[] = {
        CFG_FUNC(CFG_PARAM_CONNECTION, redis_connection_func),
        CFG_INT(CFG_PARAM_TIMEOUT, 0, CFGF_NODEFAULT),
        CFG_STR(CFG_PARAM_USERNAME, "", CFGF_NODEFAULT),
        CFG_STR(CFG_PARAM_PASSWORD, "", CFGF_NODEFAULT),
        CFG_END()
    };

    cfg_opt_t redis_opts[] = {
        CFG_BOOL(CFG_PARAM_USE_FUNCTIONS, cfg_false, CFGF_NODEFAULT),
        CFG_STR(CFG_PARAM_SCRIPTS_DIR, DEFAULT_SCRIPTS_DIR, CFGF_NONE),
        CFG_SEC(CFG_SEC_WRITE, redis_pool_opts, CFGF_NONE),
        CFG_SEC(CFG_SEC_READ, redis_pool_opts, CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t opts[] {
        CFG_INT(CFG_PARAM_EXPIRES_MIN, 0, CFGF_NODEFAULT),
        CFG_INT(CFG_PARAM_EXPIRES_MAX, 0, CFGF_NODEFAULT),
        CFG_INT(CFG_PARAM_EXPIRES_DEFAULT, 0, CFGF_NODEFAULT),
        CFG_INT(CFG_PARAM_KEEPALIVE_INTERVAL, DEFAULT_REGISTRAR_KEEPALIVE_INTERVAL, CFGF_NONE),
        CFG_INT(CFG_PARAM_BINDINGS_MAX, DEFAULT_BINDINGS_MAX, CFGF_NONE),
        CFG_INT(CFG_PARAM_KEEPALIVE_FAILURE_CODE, DEFAULT_KEEPALIVE_FAILURE_CODE, CFGF_NONE),
        CFG_SEC(CFG_SEC_REDIS, redis_opts, CFGF_NONE),
        CFG_END()
    };

    cfg_t *cfg = cfg_init(opts, CFGF_NONE);
    if(!cfg) return -1;

    switch(cfg_parse_buf(cfg, config.c_str())) {
    case CFG_SUCCESS:
        break;
    case CFG_PARSE_ERROR:
        ERROR("configuration of module %s parse error",MOD_NAME);
        cfg_free(cfg);
        return -1;
    default:
        ERROR("unexpected error on configuration of module %s processing",MOD_NAME);
        cfg_free(cfg);
        return -1;
    }

    int res = obj->configure(cfg);
    cfg_free(cfg);
    return res;
}

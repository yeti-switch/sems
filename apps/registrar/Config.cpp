#include "Config.h"
#include <log.h>

int SipRegistrarConfig::parse(const string& config, list<Configurable *> objs)
{
    int res = 0;

    cfg_opt_t redis_pool_opts[] = {
        CFG_STR(CFG_PARAM_HOST, DEFAULT_REDIS_HOST, CFGF_NONE),
        CFG_INT(CFG_PARAM_PORT, DEFAULT_REDIS_PORT, CFGF_NONE),
        CFG_INT(CFG_PARAM_TIMEOUT, 0, CFGF_NODEFAULT),
        CFG_STR(CFG_PARAM_USERNAME, "", CFGF_NODEFAULT),
        CFG_STR(CFG_PARAM_PASSWORD, "", CFGF_NODEFAULT),
        CFG_END()
    };

    cfg_opt_t redis_opts[] = {
        CFG_BOOL(CFG_PARAM_USE_FUNCTIONS, cfg_false, CFGF_NODEFAULT),
        CFG_SEC(CFG_SEC_WRITE, redis_pool_opts, CFGF_NONE),
        CFG_SEC(CFG_SEC_READ, redis_pool_opts, CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t opts[] {
        CFG_INT(CFG_PARAM_EXPIRES_MIN, 0, CFGF_NODEFAULT),
        CFG_INT(CFG_PARAM_EXPIRES_MAX, 0, CFGF_NODEFAULT),
        CFG_INT(CFG_PARAM_EXPIRES_DEFAULT, 0, CFGF_NODEFAULT),
        CFG_INT(CFG_PARAM_KEEPALIVE_INTERVAL, DEFAULT_REGISTRAR_KEEPALIVE_INTERVAL, CFGF_NONE),
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

    for(auto conj_obj : objs) {
        res = conj_obj->configure(cfg);
        if(res == -1)
            break;
    }

    cfg_free(cfg);
    return res;
}

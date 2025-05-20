#include "SipRegistrarConfig.h"
#include <log.h>
#include <AmUtils.h>

int SipRegistrarConfig::parse(const string& config, Configurable* obj)
{
    cfg_opt_t redis_pool_opts[] = {
        CFG_STR_LIST(CFG_PARAM_HOSTS, 0, CFGF_NODEFAULT),
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
        CFG_BOOL(CFG_PARAM_PROCESS_SUBSCRIPTIONS, cfg_false, CFGF_NONE),
        CFG_STR_LIST(CFG_PARAM_HEADERS, 0, CFGF_NONE),
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

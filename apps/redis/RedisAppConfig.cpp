#include "RedisAppConfig.h"
#include <log.h>

int RedisAppConfig::parse(const string& config, Configurable* obj)
{
    cfg_opt_t opts[] {
        CFG_INT(CFG_PARAM_MAX_BATCH_SIZE, DEFAULT_MAX_BATCH_SIZE, CFGF_NONE),
        CFG_INT(CFG_PARAM_BATCH_TIMEOUT, DEFAULT_BATCH_TIMEOUT, CFGF_NONE),
        CFG_INT(CFG_PARAM_MAX_QUEUE_SIZE, DEFAULT_MAX_QUEUE_SIZE, CFGF_NONE),
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

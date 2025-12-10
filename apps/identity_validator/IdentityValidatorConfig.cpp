#include "IdentityValidatorConfig.h"
#include <ampi/PostgreSqlAPI.h>
#include <log.h>

int IdentityValidatorConfig::parse(const string &config, Configurable *obj)
{
    cfg_opt_t pg_pool_opts[]{ CFG_STR(CFG_PARAM_HOST, "127.0.0.1", CFGF_NONE),
                              CFG_INT(CFG_PARAM_PORT, 5432, CFGF_NONE),
                              CFG_STR(CFG_PARAM_NAME, "yeti", CFGF_NONE),
                              CFG_STR(CFG_PARAM_USER, "yeti", CFGF_NONE),
                              CFG_STR(CFG_PARAM_PASS, "yeti", CFGF_NONE),
                              CFG_INT(CFG_PARAM_KEEPALIVE_INTERVAL, PG_DEFAULT_KEEPALIVES_INTERVAL, CFGF_NONE),
                              CFG_INT(CFG_PARAM_STATEMENT_TIMEOUT, PG_DEFAULT_WAIT_TIME, CFGF_NONE),
                              CFG_END() };


    cfg_opt_t opts[]{ CFG_STR(CFG_PARAM_HTTP_DESTINATIION, DEFAULT_HTTP_DESTINATIION, CFGF_NONE),
                      CFG_INT(CFG_PARAM_EXPIRES, DEFAULT_EXPIRES, CFGF_NONE),
                      CFG_INT(CFG_PARAM_CERTS_CACHE_TTL, DEFAULT_CERTS_CACHE_TTL, CFGF_NONE),
                      CFG_INT(CFG_PARAM_CERTS_CACHE_FAILED_TTL, DEFAULT_CACHE_FAILED_TTL, CFGF_NONE),
                      CFG_INT(CFG_PARAM_CERTS_CACHE_FAILED_VERIFY_TTL, DEFAULT_CACHE_FAILED_VERIFY_TTLS, CFGF_NONE),
                      CFG_STR(CFG_PARAM_PG_SCHEMA_NAME, "", CFGF_NONE),
                      CFG_STR(CFG_PARAM_TRUSTED_CERTS_REQ, DEFAULT_TRUSTED_CERT_REQ, CFGF_NONE),
                      CFG_STR(CFG_PARAM_TRUSTED_REPOS_REQ, DEFAULT_TRUSTED_REPO_REQ, CFGF_NONE),
                      CFG_SEC(CFG_SECTION_DB, pg_pool_opts, CFGF_NONE),
                      CFG_END() };

    cfg_t *cfg = cfg_init(opts, CFGF_NONE);
    if (!cfg)
        return -1;

    switch (cfg_parse_buf(cfg, config.c_str())) {
    case CFG_SUCCESS: break;
    case CFG_PARSE_ERROR:
        ERROR("configuration of module %s parse error", MOD_NAME);
        cfg_free(cfg);
        return -1;
    default:
        ERROR("unexpected error on configuration of module %s processing", MOD_NAME);
        cfg_free(cfg);
        return -1;
    }

    int res = obj->configure(cfg);
    cfg_free(cfg);
    return res;
    return 0;
}

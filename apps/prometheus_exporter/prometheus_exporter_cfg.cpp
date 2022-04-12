#include "prometheus_exporter_cfg.h"

extern int label_func(cfg_t *cfg, cfg_opt_t *opt, int argc, const char **argv);

static cfg_opt_t acl[]
{
    CFG_STR_LIST(PARAM_WHITELIST, 0, CFGF_NODEFAULT),
    CFG_STR(PARAM_METHOD, "", CFGF_NODEFAULT),
    CFG_END()
};

cfg_opt_t prometheus_exporter_opt[] {
    CFG_STR(PARAM_ADDRESS, "", CFGF_NODEFAULT),
    CFG_INT(PARAM_PORT, DEFAULT_PORT, CFGF_NONE),
    CFG_STR(PARAM_PREFIX, VALUE_SEMS, CFGF_NONE),
    //CFG_BOOL(PARAM_OMIT_NOW_TIMESTAMP, cfg_true, CFGF_NONE),
    //CFG_BOOL(PARAM_OMIT_UPDATE_TIMESTAMP, cfg_true, CFGF_NONE),
    CFG_FUNC(PARAM_LABEL, &label_func),
    CFG_SEC(SECTION_ACL, acl, CFGF_NODEFAULT),
    CFG_END()
};

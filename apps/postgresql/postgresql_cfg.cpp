#include "postgresql_cfg.h"

cfg_opt_t pg_opt[] {
    CFG_STR(PARAM_LOG_DIR_NAME, "", CFGF_NONE),
    CFG_INT(PARAM_LOG_TIME_NAME, DEFAULT_LOG_TIME, CFGF_NONE),
    CFG_END()
};

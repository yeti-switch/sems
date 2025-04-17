#include "postgresql_cfg.h"
#include "ampi/PostgreSqlAPI.h"

cfg_opt_t pg_opt[] {
    CFG_STR(PARAM_LOG_DIR_NAME, "", CFGF_NONE),
    CFG_INT(PARAM_LOG_TIME_NAME, DEFAULT_LOG_TIME, CFGF_NONE),
    CFG_STR(PARAM_EVENTS_QUEUE_NAME, POSTGRESQL_QUEUE, CFGF_NONE),
    CFG_BOOL(PARAM_LOG_PG_EVENTS_NAME, cfg_false, CFGF_NONE),
    CFG_END()
};

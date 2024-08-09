#include "Config.h"

cfg_opt_t pair_opts[] =
{
    CFG_STR(CFG_OPT_QUERY, "", CFGF_NONE),
    CFG_STR(CFG_OPT_RESPONSE, "", CFGF_NONE),
    CFG_END()
};

cfg_opt_t map_opts[] =
{
    CFG_SEC(CFG_OPT_PAIR, pair_opts, CFGF_MULTI),
    CFG_END()
};

cfg_opt_t pg_opts[] =
{
    CFG_SEC(CFG_OPT_MAP, map_opts, CFGF_NONE),
    CFG_END()
};

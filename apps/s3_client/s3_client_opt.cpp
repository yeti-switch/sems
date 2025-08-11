#include "s3_client_opt.h"

cfg_opt_t s3_client_opt[] = { CFG_STR(PARAM_ACCESS_KEY_NAME, "", CFGF_NODEFAULT),
                              CFG_STR(PARAM_SECRET_KEY_NAME, "", CFGF_NODEFAULT),
                              CFG_STR(PARAM_HOST_NAME, "", CFGF_NODEFAULT),
                              CFG_STR(PARAM_BUCKET_NAME, "", CFGF_NODEFAULT),
                              CFG_BOOL(PARAM_SECURE_NAME, cfg_true, CFGF_NODEFAULT),
                              CFG_BOOL(PARAM_VERIFY_HOST_NAME, cfg_true, CFGF_NONE),
                              CFG_BOOL(PARAM_VERIFY_PEER_NAME, cfg_true, CFGF_NONE),
                              CFG_BOOL(PARAM_VERIFY_ST_NAME, cfg_true, CFGF_NONE),
                              CFG_END() };

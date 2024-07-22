#pragma once

#include <string>
using std::string;

#define CFG_PARAM_USE_FUNCTIONS                 "use_functions"
#define CFG_PARAM_SCRIPTS_DIR                   "scripts_dir"
#define CFG_PARAM_EXPIRES_MIN                   "expires_min"
#define CFG_PARAM_EXPIRES_MAX                   "expires_max"
#define CFG_PARAM_EXPIRES_DEFAULT               "expires_default"
#define CFG_PARAM_HOST                          "host"
#define CFG_PARAM_PORT                          "port"
#define CFG_PARAM_TIMEOUT                       "timeout"
#define CFG_PARAM_USERNAME                      "username"
#define CFG_PARAM_PASSWORD                      "password"
#define CFG_PARAM_KEEPALIVE_INTERVAL            "keepalive_interval"

#define CFG_SEC_REDIS                           "redis"
#define CFG_SEC_WRITE                           "write"
#define CFG_SEC_READ                            "read"

#define DEFAULT_SCRIPTS_DIR                     "/etc/sems/scripts"
#define DEFAULT_REGISTRAR_KEEPALIVE_INTERVAL    60
#define DEFAULT_REDIS_HOST                      "127.0.0.1"
#define DEFAULT_REDIS_PORT                      6379

#include <confuse.h>

class Configurable
{
  public:
    virtual int configure(cfg_t* cfg) = 0;
};

class SipRegistrarConfig
{
  public:
    static int parse(const string& config, Configurable* obj);
};

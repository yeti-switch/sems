#pragma once

#include <string>
using std::string;

#define CFG_PARAM_MAX_BATCH_SIZE    "max_batch_size"
#define CFG_PARAM_BATCH_TIMEOUT     "batch_timeout"
#define CFG_PARAM_MAX_QUEUE_SIZE    "max_queue_size"

#define DEFAULT_MAX_BATCH_SIZE  10
#define DEFAULT_BATCH_TIMEOUT   100
#define DEFAULT_MAX_QUEUE_SIZE  200

#include <confuse.h>

class Configurable
{
  public:
    virtual int configure(cfg_t* cfg) = 0;
};

class RedisAppConfig
{
  public:
    static int parse(const string& config, Configurable* obj);
};

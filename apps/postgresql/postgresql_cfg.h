#pragma once

#include <confuse.h>

#define DEFAULT_LOG_TIME 10 // in sec

#define PARAM_LOG_DIR_NAME       "connection_log_dir"
#define PARAM_LOG_TIME_NAME      "connection_log_time"
#define PARAM_EVENTS_QUEUE_NAME  "events_queue_name"
#define PARAM_LOG_PG_EVENTS_NAME "log_pg_events"

extern cfg_opt_t pg_opt[];

#ifndef PROMETHEUS_EXPORTER_CFG_H
#define PROMETHEUS_EXPORTER_CFG_H

#include <confuse.h>

#define PARAM_ADDRESS            "address"
#define PARAM_PORT               "port"
#define PARAM_LABEL              "label"
#define PARAM_WHITELIST          "whitelist"
#define PARAM_METHOD             "method"
#define PARAM_PREFIX             "metrics_prefix"

//#define PARAM_OMIT_NOW_TIMESTAMP    "omit_now_timestamp"
//#define PARAM_OMIT_UPDATE_TIMESTAMP "omit_update_timestamp"

#define SECTION_ACL     "acl"

#define VALUE_DROP      "drop"
#define VALUE_REJECT    "reject"
#define VALUE_SEMS      "sems"

#define DEFAULT_PORT    8080

extern cfg_opt_t prometheus_exporter_opt[];

#endif/*PROMETHEUS_EXPORTER_CFG_H*/

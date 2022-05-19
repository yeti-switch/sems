#pragma once

#include <confuse.h>

#define RECONNECT_DEFAULT_INTERVAL  5
#define QUERY_DEFAULT_TIMEOUT       5
#define SHUTDOWN_DEFAULT_CODE       503

#define SECTION_BUS_NODE_NAME       "connection"
#define SECTION_DYN_QUEUE_NAME      "dynamic_queue"
#define SECTION_METHOD_NAME         "method"
#define SECTION_ROUTING_NAME        "routing"

#define PARAM_RECONN_INT_NAME       "reconnect_interval"
#define PARAM_QUERY_TIMEOUT_NAME    "query_timeout"
#define PARAM_SHUTDOWN_CODE_NAME    "shutdown_code"
#define PARAM_SO_RCVBUF_NAME        "so_rcvbuf"
#define PARAM_SO_SNDBUF_NAME        "so_sndbuf"
#define PARAM_ADDRESS_NAME          "address"
#define PARAM_PORT_NAME             "port"
#define PARAM_APP_NAME              "app"
#define PARAM_PRIORITY_NAME         "priority"
#define PARAM_WEIGHT_NAME           "weight"
#define PARAM_BROADCAST_NAME        "broadcast"

cfg_opt_t bus_node_param[] =
{
    CFG_INT(PARAM_PRIORITY_NAME, 0, CFGF_NODEFAULT),
    CFG_INT(PARAM_WEIGHT_NAME, 0, CFGF_NONE),
    CFG_END()
};

cfg_opt_t method[] =
{
    CFG_SEC(SECTION_BUS_NODE_NAME, bus_node_param, CFGF_MULTI | CFGF_TITLE),
    CFG_BOOL(PARAM_BROADCAST_NAME, cfg_false, CFGF_NONE),
    CFG_END()
};

cfg_opt_t routing[] =
{
    CFG_SEC(SECTION_METHOD_NAME, method,  CFGF_MULTI | CFGF_TITLE),
    CFG_END()
};

cfg_opt_t bus_node[] =
{
    CFG_STR(PARAM_ADDRESS_NAME, "", CFGF_NODEFAULT),
    CFG_INT(PARAM_PORT_NAME, 0, CFGF_NODEFAULT),
    CFG_END()
};

cfg_opt_t dyn_queue[] =
{
    CFG_STR(PARAM_APP_NAME, "", CFGF_NODEFAULT),
    CFG_END()
};

cfg_opt_t bus_client_opts[] =
{
    CFG_INT(PARAM_RECONN_INT_NAME, RECONNECT_DEFAULT_INTERVAL, CFGF_NONE),
    CFG_INT(PARAM_QUERY_TIMEOUT_NAME, QUERY_DEFAULT_TIMEOUT, CFGF_NONE),
    CFG_INT(PARAM_SHUTDOWN_CODE_NAME, SHUTDOWN_DEFAULT_CODE, CFGF_NONE),
    CFG_INT(PARAM_SO_RCVBUF_NAME, 0, CFGF_NONE),
    CFG_INT(PARAM_SO_SNDBUF_NAME, 0, CFGF_NONE),
    CFG_SEC(SECTION_DYN_QUEUE_NAME, dyn_queue, CFGF_MULTI | CFGF_TITLE),
    CFG_SEC(SECTION_BUS_NODE_NAME, bus_node, CFGF_MULTI | CFGF_TITLE),
    CFG_SEC(SECTION_ROUTING_NAME, routing, CFGF_NODEFAULT),
    CFG_END()
};

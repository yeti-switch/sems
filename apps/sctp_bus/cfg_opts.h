#pragma once

#include <confuse.h>

#define SCTP_BUS_DEFAULT_PORT 10101
#define SCTP_BUS_DEFAULT_RECONNECT_INTERVAL 3

char sctp_bus_default_address[] = "127.0.0.1";

char opt_name_address[] = "address";
char opt_name_port[] = "port";

char section_name_listen[] = "listen";

char section_name_neighbours[] = "neighbours";
char opt_name_default_port[] = "port";
char opt_name_default_address[] = "address";
char opt_name_reconnect_interval[] = "reconnect_interval";
char section_name_node[] = "node";

static cfg_opt_t listen_opts[] = {
    CFG_STR(opt_name_address,sctp_bus_default_address,CFGF_NONE),
    CFG_INT(opt_name_port,SCTP_BUS_DEFAULT_PORT,CFGF_NONE),
    CFG_END()
};

static cfg_opt_t node_opts[] = {
    CFG_STR(opt_name_address,NULL,CFGF_NONE),
    CFG_INT(opt_name_port,0,CFGF_NONE),
    CFG_END()
};

static cfg_opt_t neighbours_opts[] = {
    CFG_INT(opt_name_default_port,SCTP_BUS_DEFAULT_PORT,CFGF_NONE),
    CFG_INT(opt_name_reconnect_interval,SCTP_BUS_DEFAULT_RECONNECT_INTERVAL,CFGF_NONE),
    CFG_STR(opt_name_default_address,NULL,CFGF_NONE),
    CFG_SEC(section_name_node,node_opts, CFGF_MULTI | CFGF_TITLE),
    CFG_END()
};

static cfg_opt_t sctp_bus_opts[] = {
    CFG_SEC(section_name_listen,listen_opts, CFGF_NONE),
    CFG_SEC(section_name_neighbours,neighbours_opts, CFGF_NONE),
    CFG_END()
};

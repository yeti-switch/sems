#include "AmLcConfig.h"
#include <string.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "sip/ip_util.h"

#define SECTION_SIGIF_NAME           "signaling-interfaces"
#define SECTION_MEDIAIF_NAME         "media-interfaces"
#define SECTION_IF_NAME              "interface"
#define SECTION_DEFAULT_MEDIAIF_NAME "default-media-interface"
#define SECTION_IP4_NAME             "ip4"
#define SECTION_IP6_NAME             "ip6"
#define SECTION_RTSP_NAME            "rtsp"
#define SECTION_RTP_NAME             "rtp"
#define SECTION_SIP_TCP_NAME         "sip-tcp"
#define SECTION_SIP_UDP_NAME         "sip-udp"
#define SECTION_ADDRESS_NAME         "address"
#define SECTION_LOW_PORT_NAME        "low-port"
#define SECTION_HIGH_PORT_NAME       "high-port"
#define SECTION_PORT_NAME            "port"
#define SECTION_DSCP_NAME            "dscp"
#define SECTION_USE_RAW_NAME         "use-raw-sockets"
#define SECTION_STAT_CL_PORT_NAME    "static-client-port"
#define SECTION_FORCE_VIA_PORT_NAME  "force-via-address"
#define SECTION_FORCE_OBD_IF_NAME    "force_outbound_if"
#define SECTION_PUBLIC_ADDR_NAME     "public_address"
#define SECTION_OPT_NAME             "options-acl"
#define SECTION_ORIGACL_NAME         "origination-acl"
#define SECTION_CONNECT_TIMEOUT_NAME "connect-timeout"
#define SECTION_IDLE_TIMEOUT_NAME    "idle-timeout"
#define SECTION_WHITELIST_NAME       "whitelist"
#define SECTION_METHOD_NAME          "method"

#define VALUE_OFF                    "off"
#define VALUE_ON                     "on"
#define VALUE_DROP                   "drop"
#define VALUE_REJECT                 "reject"

#define CONF_FILE_PATH               "/etc/sems/sems.cfg"

int validate_bool_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    bool valid = (value == VALUE_OFF || value == VALUE_ON);
    if(!valid) {
        ERROR("invalid value \'%s\' of option \'%s\' - must be \'on\' or \'off\'", value.c_str(), opt->name);
    }
    return valid ? 0 : 1;
}

int validate_method_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    bool valid = (value == VALUE_DROP || value == VALUE_REJECT);
    if(!valid) {
        ERROR("invalid value \'%s\' of option \'%s\' - must be \'drop\' or \'reject\'", value.c_str(), opt->name);
    }
    return valid ? 0 : 1;
}

int validate_ip6_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    sockaddr_storage addr;
    if(!am_inet_pton(value.c_str(), &addr)){
        ERROR("invalid value \'%s\' of address", value.c_str());
        return 1;
    }

    bool valid = addr.ss_family == AF_INET6;
    if(!valid) {
        ERROR("invalid value \'%s\' of address: not ip6 address", value.c_str());
    }
    return valid ? 0 : 1;
}

int validate_ip4_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    sockaddr_storage addr;
    if(!am_inet_pton(value.c_str(), &addr)){
        ERROR("invalid value \'%s\' of address", value.c_str());
        return 1;
    }

    bool valid = addr.ss_family == AF_INET;
    if(!valid) {
        ERROR("invalid value \'%s\' of address: not ip4 address", value.c_str());
    }
    return valid ? 0 : 1;
}

AmLcConfig::AmLcConfig()
{
    cfg_opt_t acl[]
    {
        CFG_STR_LIST(SECTION_WHITELIST_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(SECTION_METHOD_NAME, "", CFGF_NODEFAULT),
        CFG_END()
    };

    cfg_opt_t rtsp[] =
    {
        CFG_STR(SECTION_ADDRESS_NAME, "", CFGF_NODEFAULT),
        CFG_INT(SECTION_LOW_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_INT(SECTION_HIGH_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(SECTION_PUBLIC_ADDR_NAME, "", CFGF_NONE),
        CFG_STR(SECTION_USE_RAW_NAME, "", CFGF_NONE),
        CFG_STR(SECTION_FORCE_OBD_IF_NAME, "", CFGF_NONE),
        CFG_STR(SECTION_FORCE_VIA_PORT_NAME, "", CFGF_NONE),
        CFG_STR(SECTION_STAT_CL_PORT_NAME, "", CFGF_NONE),
        CFG_INT(SECTION_DSCP_NAME, 0, CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t rtp[] =
    {
        CFG_STR(SECTION_ADDRESS_NAME, "", CFGF_NODEFAULT),
        CFG_INT(SECTION_LOW_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(SECTION_PUBLIC_ADDR_NAME, "", CFGF_NONE),
        CFG_INT(SECTION_HIGH_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(SECTION_USE_RAW_NAME, "", CFGF_NONE),
        CFG_STR(SECTION_FORCE_OBD_IF_NAME, "", CFGF_NONE),
        CFG_STR(SECTION_FORCE_VIA_PORT_NAME, "", CFGF_NONE),
        CFG_STR(SECTION_STAT_CL_PORT_NAME, "", CFGF_NONE),
        CFG_INT(SECTION_DSCP_NAME, 0, CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t sip_tcp[] =
    {
        CFG_STR(SECTION_ADDRESS_NAME, "", CFGF_NODEFAULT),
        CFG_INT(SECTION_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(SECTION_USE_RAW_NAME, "", CFGF_NONE),
        CFG_STR(SECTION_FORCE_OBD_IF_NAME, "", CFGF_NONE),
        CFG_STR(SECTION_FORCE_VIA_PORT_NAME, "", CFGF_NONE),
        CFG_STR(SECTION_STAT_CL_PORT_NAME, "", CFGF_NONE),
        CFG_STR(SECTION_PUBLIC_ADDR_NAME, "", CFGF_NONE),
        CFG_INT(SECTION_DSCP_NAME, 0, CFGF_NONE),
        CFG_INT(SECTION_CONNECT_TIMEOUT_NAME, 0, CFGT_NONE),
        CFG_INT(SECTION_IDLE_TIMEOUT_NAME, 0, CFGT_NONE),
        CFG_END()
    };

    cfg_opt_t sip_udp[] =
    {
        CFG_STR(SECTION_ADDRESS_NAME, "", CFGF_NODEFAULT),
        CFG_INT(SECTION_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(SECTION_USE_RAW_NAME, "", CFGF_NONE),
        CFG_STR(SECTION_FORCE_OBD_IF_NAME, "", CFGF_NONE),
        CFG_STR(SECTION_FORCE_VIA_PORT_NAME, "", CFGF_NONE),
        CFG_STR(SECTION_PUBLIC_ADDR_NAME, "", CFGF_NONE),
        CFG_STR(SECTION_STAT_CL_PORT_NAME, "", CFGF_NONE),
        CFG_INT(SECTION_DSCP_NAME, 0, CFGF_NONE),
        CFG_SEC(SECTION_OPT_NAME, acl, CFGF_NODEFAULT),
        CFG_SEC(SECTION_ORIGACL_NAME, acl, CFGF_NODEFAULT),
        CFG_END()
    };

    cfg_opt_t ip[] =
    {
        CFG_SEC(SECTION_RTSP_NAME, rtsp, CFGF_NODEFAULT),
        CFG_SEC(SECTION_RTP_NAME, rtp, CFGF_NODEFAULT),
        CFG_SEC(SECTION_SIP_TCP_NAME, sip_tcp, CFGF_NODEFAULT),
        CFG_SEC(SECTION_SIP_UDP_NAME, sip_udp, CFGF_NODEFAULT),
        CFG_END()
    };

    cfg_opt_t interface[] =
    {
        CFG_STR(SECTION_DEFAULT_MEDIAIF_NAME, "", CFGF_NONE),
        CFG_SEC(SECTION_IP4_NAME, ip, CFGF_NODEFAULT),
        CFG_SEC(SECTION_IP6_NAME, ip, CFGF_NODEFAULT),
        CFG_END()
    };

    cfg_opt_t interfaces[] =
    {
        CFG_SEC(SECTION_IF_NAME, interface, CFGF_MULTI | CFGF_TITLE),
        CFG_END()
    };

    cfg_opt_t opt[] =
    {
        CFG_SEC(SECTION_SIGIF_NAME, interfaces, CFGF_NODEFAULT),
        CFG_SEC(SECTION_MEDIAIF_NAME, interfaces, CFGF_NODEFAULT),
        CFG_END()
    };

    m_cfg = cfg_init(opt, 0);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_SIP_TCP_NAME "|" SECTION_USE_RAW_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_SIP_TCP_NAME "|" SECTION_FORCE_OBD_IF_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_SIP_TCP_NAME "|" SECTION_FORCE_VIA_PORT_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_SIP_TCP_NAME "|" SECTION_STAT_CL_PORT_NAME, validate_bool_func);

    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_SIP_UDP_NAME "|" SECTION_USE_RAW_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_SIP_UDP_NAME "|" SECTION_FORCE_OBD_IF_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_SIP_UDP_NAME "|" SECTION_FORCE_VIA_PORT_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_SIP_UDP_NAME "|" SECTION_STAT_CL_PORT_NAME, validate_bool_func);

    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_SIP_TCP_NAME "|" SECTION_USE_RAW_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_SIP_TCP_NAME "|" SECTION_FORCE_OBD_IF_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_SIP_TCP_NAME "|" SECTION_FORCE_VIA_PORT_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_SIP_TCP_NAME "|" SECTION_STAT_CL_PORT_NAME, validate_bool_func);

    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_SIP_UDP_NAME "|" SECTION_USE_RAW_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_SIP_UDP_NAME "|" SECTION_FORCE_OBD_IF_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_SIP_UDP_NAME "|" SECTION_FORCE_VIA_PORT_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_SIP_UDP_NAME "|" SECTION_STAT_CL_PORT_NAME, validate_bool_func);

    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_RTP_NAME "|" SECTION_USE_RAW_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_RTP_NAME "|" SECTION_FORCE_OBD_IF_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_RTP_NAME "|" SECTION_FORCE_VIA_PORT_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_RTP_NAME "|" SECTION_STAT_CL_PORT_NAME, validate_bool_func);

    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_RTSP_NAME "|" SECTION_USE_RAW_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_RTSP_NAME "|" SECTION_FORCE_OBD_IF_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_RTSP_NAME "|" SECTION_FORCE_VIA_PORT_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_RTSP_NAME "|" SECTION_STAT_CL_PORT_NAME, validate_bool_func);

    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_RTP_NAME "|" SECTION_USE_RAW_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_RTP_NAME "|" SECTION_FORCE_OBD_IF_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_RTP_NAME "|" SECTION_FORCE_VIA_PORT_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_RTP_NAME "|" SECTION_STAT_CL_PORT_NAME, validate_bool_func);

    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_RTSP_NAME "|" SECTION_USE_RAW_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_RTSP_NAME "|" SECTION_FORCE_OBD_IF_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_RTSP_NAME "|" SECTION_FORCE_VIA_PORT_NAME, validate_bool_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_RTSP_NAME "|" SECTION_STAT_CL_PORT_NAME, validate_bool_func);

    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|"
                                 SECTION_SIP_UDP_NAME "|" SECTION_OPT_NAME "|" SECTION_METHOD_NAME, validate_method_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|"
                                 SECTION_SIP_UDP_NAME "|" SECTION_OPT_NAME "|" SECTION_METHOD_NAME, validate_method_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|"
                                 SECTION_SIP_TCP_NAME "|" SECTION_OPT_NAME "|" SECTION_METHOD_NAME, validate_method_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|"
                                 SECTION_SIP_TCP_NAME "|" SECTION_OPT_NAME "|" SECTION_METHOD_NAME, validate_method_func);

    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|"
                                 SECTION_SIP_TCP_NAME "|" SECTION_ADDRESS_NAME, validate_ip6_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|"
                                 SECTION_SIP_UDP_NAME "|" SECTION_ADDRESS_NAME, validate_ip6_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|"
                                 SECTION_SIP_TCP_NAME "|" SECTION_ADDRESS_NAME, validate_ip4_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|"
                                 SECTION_SIP_UDP_NAME "|" SECTION_ADDRESS_NAME, validate_ip4_func);
}

AmLcConfig::~AmLcConfig()
{
    if(m_cfg) {
        cfg_free(m_cfg);
    }
}

int AmLcConfig::readConfiguration()
{
    sip_ifs.clear();

    switch(cfg_parse(m_cfg, CONF_FILE_PATH)) {
    case CFG_SUCCESS:
        break;
    case CFG_FILE_ERROR:
        ERROR("failed to open configuration file: %s (%s)",
            CONF_FILE_PATH, strerror(errno));
        return -1;
    case CFG_PARSE_ERROR:
        ERROR("failed to parse configuration file: %s", CONF_FILE_PATH);
        return -1;
    default:
        ERROR("got unexpected error on configuration file processing: %s", CONF_FILE_PATH);
        return -1;
    }

    cfg_t* sigif = cfg_getsec(m_cfg, SECTION_SIGIF_NAME);
    if(!sigif) {
        ERROR(SECTION_SIGIF_NAME " absent\n");
        return -1;
    }

    int ifCount = cfg_size(sigif, SECTION_IF_NAME);
    for(int i = 0; i < ifCount; i++) {
        SIP_interface sip_if;
        cfg_t* if_ = cfg_getnsec(sigif, SECTION_IF_NAME, i);
        sip_if.name = if_->title;
        sip_if.default_media_if = cfg_getstr(if_, SECTION_DEFAULT_MEDIAIF_NAME);
        if(cfg_size(if_, SECTION_IP4_NAME)) {
            cfg_t* ip4 = cfg_getsec(if_, SECTION_IP4_NAME);
            if(cfg_size(ip4, SECTION_SIP_UDP_NAME)) {
                cfg_t* cfg = cfg_getsec(ip4, SECTION_SIP_UDP_NAME);
                SIP_info* info = (SIP_info*)readInterface(cfg, sip_if.name, IP_info::IPv4);
                sip_if.proto_info.push_back(info);
            }
            if(cfg_size(ip4, SECTION_SIP_TCP_NAME)) {
                cfg_t* cfg = cfg_getsec(ip4, SECTION_SIP_TCP_NAME);
                SIP_info* info = (SIP_info*)readInterface(cfg, sip_if.name, IP_info::IPv4);
                sip_if.proto_info.push_back(info);
            }
        }
        if(cfg_size(if_, SECTION_IP6_NAME)) {
            cfg_t* ip4 = cfg_getsec(if_, SECTION_IP6_NAME);
            if(cfg_size(ip4, SECTION_SIP_UDP_NAME)) {
                cfg_t* cfg = cfg_getsec(ip4, SECTION_SIP_UDP_NAME);
                SIP_info* info = (SIP_info*)readInterface(cfg, sip_if.name, IP_info::IPv6);
                sip_if.proto_info.push_back(info);
            }
            if(cfg_size(ip4, SECTION_SIP_TCP_NAME)) {
                cfg_t* cfg = cfg_getsec(ip4, SECTION_SIP_TCP_NAME);
                SIP_info* info = (SIP_info*)readInterface(cfg, sip_if.name, IP_info::IPv6);
                sip_if.proto_info.push_back(info);
            }
        }
        if(!sip_if.proto_info.empty()) {
            sip_ifs.push_back(sip_if);
        }
    }

    cfg_t* mediaif = cfg_getsec(m_cfg, SECTION_MEDIAIF_NAME);
    ifCount = cfg_size(mediaif, SECTION_IF_NAME);
    for(int i = 0; i < ifCount; i++) {
        MEDIA_interface media_if;
        cfg_t* if_ = cfg_getnsec(mediaif, SECTION_IF_NAME, i);
        media_if.name = if_->title;
        if(cfg_size(if_, SECTION_IP4_NAME)) {
            cfg_t* ip4 = cfg_getsec(if_, SECTION_IP4_NAME);
            if(cfg_size(ip4, SECTION_RTP_NAME)) {
                cfg_t* cfg = cfg_getsec(ip4, SECTION_RTP_NAME);
                MEDIA_info* info = (MEDIA_info*)readInterface(cfg, media_if.name, IP_info::IPv4);
                media_if.proto_info.push_back(info);
            }
            if(cfg_size(ip4, SECTION_RTSP_NAME)) {
                cfg_t* cfg = cfg_getsec(ip4, SECTION_RTSP_NAME);
                MEDIA_info* info = (MEDIA_info*)readInterface(cfg, media_if.name, IP_info::IPv4);
                media_if.proto_info.push_back(info);
            }
        }
        if(cfg_size(if_, SECTION_IP6_NAME)) {
            cfg_t* ip4 = cfg_getsec(if_, SECTION_IP6_NAME);
            if(cfg_size(ip4, SECTION_RTP_NAME)) {
                cfg_t* cfg = cfg_getsec(ip4, SECTION_RTP_NAME);
                MEDIA_info* info = (MEDIA_info*)readInterface(cfg, media_if.name, IP_info::IPv6);
                media_if.proto_info.push_back(info);
            }
            if(cfg_size(ip4, SECTION_RTSP_NAME)) {
                cfg_t* cfg = cfg_getsec(ip4, SECTION_RTSP_NAME);
                MEDIA_info* info = (MEDIA_info*)readInterface(cfg, media_if.name, IP_info::IPv6);
                media_if.proto_info.push_back(info);
            }
        }
        if(!media_if.proto_info.empty()) {
            media_ifs.push_back(media_if);
        }
    }

    if(checkSipInterfaces()) {
        return -1;
    }
    return 0;
}

IP_info* AmLcConfig::readInterface(cfg_t* cfg, const std::string& if_name, IP_info::IP_type ip_type)
{
    IP_info* info;
    SIP_info* sinfo = 0;
    SIP_UDP_info* suinfo = 0;
    SIP_TCP_info* stinfo = 0;
    MEDIA_info* mediainfo = 0;
    if(strcmp(cfg->name, SECTION_SIP_UDP_NAME) == 0) {
        info = sinfo = suinfo = new SIP_UDP_info();
    } else if(strcmp(cfg->name, SECTION_SIP_TCP_NAME) == 0) {
        info = sinfo = stinfo = new SIP_TCP_info();
    } else if(strcmp(cfg->name, SECTION_RTP_NAME) == 0) {
        info = mediainfo = new RTP_info();
    } else if(strcmp(cfg->name, SECTION_RTSP_NAME) == 0) {
        info = mediainfo = new RTSP_info();
    } else {
        return 0;
    }

    info->type_ip = ip_type;
    info->local_ip = cfg_getstr(cfg, SECTION_ADDRESS_NAME);
    if(cfg_size(cfg, SECTION_PUBLIC_ADDR_NAME)) {
        info->public_ip = cfg_getstr(cfg, SECTION_PUBLIC_ADDR_NAME);
    }
    if(cfg_size(cfg, SECTION_USE_RAW_NAME)) {
        std::string value = cfg_getstr(cfg, SECTION_USE_RAW_NAME);
        if(value == VALUE_ON) {
            info->sig_sock_opts |= trsp_socket::use_raw_sockets;
        }
    }
    if(cfg_size(cfg, SECTION_FORCE_VIA_PORT_NAME)) {
        std::string value = cfg_getstr(cfg, SECTION_FORCE_VIA_PORT_NAME);
        if(value == VALUE_ON) {
            info->sig_sock_opts |= trsp_socket::force_via_address;
        }
    }
    if(cfg_size(cfg, SECTION_STAT_CL_PORT_NAME)) {
        std::string value = cfg_getstr(cfg, SECTION_STAT_CL_PORT_NAME);
        if(value == VALUE_ON) {
            info->sig_sock_opts |= trsp_socket::static_client_port;
        }
    }
    if(cfg_size(cfg, SECTION_FORCE_OBD_IF_NAME)) {
        std::string value = cfg_getstr(cfg, SECTION_FORCE_OBD_IF_NAME);
        if(value == VALUE_ON) {
            info->sig_sock_opts |= trsp_socket::force_outbound_if;
        }
    }
    if(cfg_size(cfg, SECTION_DSCP_NAME)) {
        info->dscp = cfg_getint(cfg, SECTION_DSCP_NAME);
        info->tos_byte = info->dscp << 2;
    }

    if(sinfo) {
        sinfo->local_port = cfg_getint(cfg, SECTION_PORT_NAME);
    }
    if(mediainfo) {
        mediainfo->high_port = cfg_getint(cfg, SECTION_HIGH_PORT_NAME);
        mediainfo->low_port = cfg_getint(cfg, SECTION_LOW_PORT_NAME);
    }

    if(stinfo && cfg_size(cfg, SECTION_CONNECT_TIMEOUT_NAME)) {
        stinfo->tcp_connect_timeout = cfg_getint(cfg, SECTION_CONNECT_TIMEOUT_NAME);
    }

    if(stinfo && cfg_size(cfg, SECTION_IDLE_TIMEOUT_NAME)) {
        stinfo->tcp_idle_timeout = cfg_getint(cfg, SECTION_IDLE_TIMEOUT_NAME);
    }

    if(cfg_size(cfg, SECTION_ORIGACL_NAME)) {
        cfg_t* acl = cfg_getsec(cfg, SECTION_ORIGACL_NAME);
        if(readAcl(acl, sinfo->acl, if_name)) {
             ERROR("error parsing invite acl for interface: %s",if_name.c_str());
             return 0;
        }
    }

    if(cfg_size(cfg, SECTION_OPT_NAME)) {
        cfg_t* opt_acl = cfg_getsec(cfg, SECTION_OPT_NAME);
        if(readAcl(opt_acl, sinfo->opt_acl, if_name)) {
            ERROR("error parsing options acl for interface: %s",if_name.c_str());
            return 0;
        }
    }
    return info;
}

int AmLcConfig::readAcl(cfg_t* cfg, trsp_acl& acl, const std::string& if_name)
{
    int networks = 0;
    for(unsigned int j = 0; j < cfg_size(cfg, SECTION_WHITELIST_NAME); j++) {
        AmSubnet net;
        std::string host = cfg_getnstr(cfg, SECTION_WHITELIST_NAME, j);
        if(!net.parse(host)) {
            return 1;
        }
        acl.add_network(net);
        networks++;
    }

    DBG("parsed %d networks from key %s",networks,if_name.c_str());

    std::string method = cfg_getstr(cfg, SECTION_METHOD_NAME);
    if(method == "drop"){
        acl.set_action(trsp_acl::Drop);
    } else if(method == "reject") {
        acl.set_action(trsp_acl::Reject);
    } else {
        ERROR("unknown acl method '%s'", method.c_str());
        return 1;
    }

    return 0;
}

int AmLcConfig::finalizeIpConfig()
{
    fillSysIntfList();

    for(auto if_iterator = sip_ifs.begin(); if_iterator != sip_ifs.end(); if_iterator++) {
        auto if_names_iterator = sip_if_names.find(if_iterator->name);
        if(if_names_iterator != sip_if_names.end()) {
            WARN("duplicate sip name interface %s", if_iterator->name.c_str());
            sip_if_names[if_iterator->name] = if_iterator - sip_ifs.begin();
        } else {
            sip_if_names.insert(std::make_pair(if_iterator->name, if_iterator - sip_ifs.begin()));
        }

        for(auto& info : if_iterator->proto_info) {
            std::string local_ip = info->local_ip;
            info->local_ip = fixIface2IP(info->local_ip, true);
            if(info->local_ip.empty()) {
                ERROR("could not determine signaling IP %s for "
                      "interface '%s'\n", local_ip.c_str(), if_iterator->name.c_str());
                return -1;
            }
            if (insertSIPInterfaceMapping(if_iterator->name, *info,if_iterator - sip_ifs.begin()) < 0 ||
                setNetInterface(*info)) {
                return -1;
            }
        }
    }

    for(auto if_iterator = media_ifs.begin(); if_iterator != media_ifs.end(); if_iterator++) {
        auto if_names_iterator = media_if_names.find(if_iterator->name);
        if(if_names_iterator != media_if_names.end()) {
            WARN("duplicate media name interface %s", if_iterator->name.c_str());
            media_if_names[if_iterator->name] = if_iterator - media_ifs.begin();
        } else {
            media_if_names.insert(std::make_pair(if_iterator->name, if_iterator - media_ifs.begin()));
        }

        for(auto& info : if_iterator->proto_info) {
            std::string local_ip = info->local_ip;
            info->local_ip = fixIface2IP(info->local_ip, true);
            if(info->local_ip.empty()) {
                ERROR("could not determine signaling IP %s for "
                      "interface '%s'\n", local_ip.c_str(), if_iterator->name.c_str());
                return -1;
            }
            if (setNetInterface(*info)) {
                return -1;
            }
        }
    }

    fillMissingLocalSIPIPfromSysIntfs();
    return 0;
}

void AmLcConfig::dump_Ifs()
{
    INFO("Signaling interfaces:");
    for(int i=0; i<(int)sip_ifs.size(); i++) {
        SIP_interface& it_ref = sip_ifs[i];
        INFO("\t(%i) name='%s'", i,it_ref.name.c_str());
        std::vector<SIP_info*>::iterator it = it_ref.proto_info.begin();
        for(; it != it_ref.proto_info.end(); it++) {
            if((*it)->type == SIP_info::TCP) {
                SIP_TCP_info* info = SIP_TCP_info::toSIP_TCP(*it);
                INFO("\t\tTCP%u/%u",
                    info->tcp_connect_timeout,
                    info->tcp_idle_timeout);
            } else {
                INFO("\t\tUDP");
            }
           INFO("\t\tLocalIP='%s'"
                ";local_port='%u'"
                ";PublicIP='%s'; DSCP=%u",
                (*it)->local_ip.c_str(),
                (*it)->local_port,
                (*it)->public_ip.c_str(),
                (*it)->dscp);
        }
    }

    INFO("Signaling address map:");
    for(std::map<std::string,unsigned short>::iterator it = local_sip_ip2if.begin();
            it != local_sip_ip2if.end(); ++it) {
        if(sip_ifs[it->second].name.empty()) {
            INFO("\t%s -> default",it->first.c_str());
        }
        else {
            INFO("\t%s -> %s",it->first.c_str(),
                 sip_ifs[it->second].name.c_str());
        }
    }

    INFO("Media interfaces:");
    for(int i=0; i<(int)media_ifs.size(); i++) {

        MEDIA_interface& it_ref = media_ifs[i];
        INFO("\t(%i) name='%s'", i,it_ref.name.c_str());
        std::vector<MEDIA_info*>::iterator it = it_ref.proto_info.begin();
        for(; it != it_ref.proto_info.end(); it++) {
            if((*it)->mtype == MEDIA_info::RTP) {
                INFO("\t\tRTP");
            } else {
                INFO("\t\tRTSP");
            }
           INFO("\t\tLocalIP='%s'"
                ";Ports=[%u;%u]"
                ";MediaCapacity=%u"
                ";PublicIP='%s'; DSCP=%u",
                (*it)->local_ip.c_str(),
                (*it)->low_port,(*it)->high_port,
                ((*it)->high_port - (*it)->low_port+1)/2,
                (*it)->public_ip.c_str(),
                (*it)->dscp);
        }
    }
}

void AmLcConfig::fillMissingLocalSIPIPfromSysIntfs()
{
    // add addresses from SysIntfList, if not present
    for(unsigned int idx = 0; idx < sip_ifs.size(); idx++) {
        std::vector<SIP_info*>::iterator info_it = sip_ifs[idx].proto_info.begin();
        for(;info_it != sip_ifs[idx].proto_info.end(); info_it++) {
            std::vector<SysIntf>::iterator intf_it = sys_ifs.begin();
            for(; intf_it != sys_ifs.end(); ++intf_it) {

                std::list<IPAddr>::iterator addr_it = intf_it->addrs.begin();
                for(; addr_it != intf_it->addrs.end(); addr_it++) {
                    if(addr_it->addr == (*info_it)->local_ip) {
                        break;
                    }
                }

                // address not in this interface
                if(addr_it == intf_it->addrs.end())
                    continue;

                // address is primary
                if(addr_it == intf_it->addrs.begin())
                    continue;

                if(local_sip_ip2if.find(intf_it->addrs.front().addr) == local_sip_ip2if.end()) {
                    DBG("mapping unmapped IP address '%s' to interface #%u \n",
                        intf_it->addrs.front().addr.c_str(), idx);
                    local_sip_ip2if[intf_it->addrs.front().addr] = idx;
                }
            }
        }
    }
}

int AmLcConfig::setNetInterface(IP_info& ip_if)
{
    for(unsigned int i=0; i < sys_ifs.size(); i++) {
        std::list<IPAddr>::iterator addr_it = sys_ifs[i].addrs.begin();
        while(addr_it != sys_ifs[i].addrs.end()) {
            if(ip_if.local_ip == addr_it->addr) {
                ip_if.net_if = sys_ifs[i].name;
                ip_if.net_if_idx = i;
                return 0;
            }
            addr_it++;
        }
    }

    // not interface found
    return -1;
}

int AmLcConfig::insertSIPInterfaceMapping(const std::string& ifname, const SIP_info& intf, int idx) {
    //SIP_If_names[intf.name] = idx;
    const std::string &if_local_ip = intf.local_ip;

    std::map<std::string,unsigned short>::iterator it = local_sip_ip2if.find(if_local_ip);
    if(it == local_sip_ip2if.end()) {
        local_sip_ip2if.emplace(if_local_ip,idx);
    } else {
        const SIP_interface& old_intf = sip_ifs[it->second];
        // two interfaces on the sample IP - the one on port 5060 has priority
        if (intf.local_port == 5060)
            local_sip_ip2if.insert(make_pair(if_local_ip,idx));
    }
    return 0;
}

std::string AmLcConfig::fixIface2IP(const std::string& dev_name, bool v6_for_sip)
{
    struct sockaddr_storage ss;
    if(am_inet_pton(dev_name.c_str(), &ss)) {
        if(v6_for_sip && (ss.ss_family == AF_INET6) && (dev_name[0] != '['))
            return "[" + dev_name + "]";
        else
            return dev_name;
    }

    for(std::vector<SysIntf>::iterator intf_it = sys_ifs.begin();
            intf_it != sys_ifs.end(); ++intf_it) {

        if(intf_it->name != dev_name)
            continue;

        if(intf_it->addrs.empty()) {
            ERROR("No IP address for interface '%s'\n",intf_it->name.c_str());
            return "";
        }

        DBG("dev_name = '%s'\n",dev_name.c_str());
        return intf_it->addrs.front().addr;
    }

    return "";
}

/** Get the list of network interfaces with the associated addresses & flags */
bool AmLcConfig::fillSysIntfList()
{
    struct ifaddrs *ifap = NULL;

    // socket to grab MTU
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) {
        ERROR("socket() failed: %s",strerror(errno));
        return false;
    }

    if(getifaddrs(&ifap) < 0) {
        ERROR("getifaddrs() failed: %s",strerror(errno));
        return false;
    }

    char host[NI_MAXHOST];
    for(struct ifaddrs *p_if = ifap; p_if != NULL; p_if = p_if->ifa_next) {
        if(p_if->ifa_addr == NULL)
            continue;

        if( (p_if->ifa_addr->sa_family != AF_INET) &&
                (p_if->ifa_addr->sa_family != AF_INET6) )
            continue;

        if( !(p_if->ifa_flags & IFF_UP) || !(p_if->ifa_flags & IFF_RUNNING) )
            continue;

        if(p_if->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)p_if->ifa_addr;
            if(IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
                // sorry, we don't support link-local addresses...
                continue;

                // convert address from kernel-style to userland
                // addr->sin6_scope_id = ntohs(*(uint16_t *)&addr->sin6_addr.s6_addr[2]);
                // addr->sin6_addr.s6_addr[2] = addr->sin6_addr.s6_addr[3] = 0;
            }
        }

        if (am_inet_ntop((const sockaddr_storage*)p_if->ifa_addr, host, NI_MAXHOST) == NULL) {
            ERROR("am_inet_ntop() failed\n");
            continue;
            // freeifaddrs(ifap);
            // return false;
        }

        string iface_name(p_if->ifa_name);
        std::vector<SysIntf>::iterator intf_it;
        for(intf_it = sys_ifs.begin(); intf_it != sys_ifs.end(); ++intf_it) {
            if(intf_it->name == iface_name)
                break;
        }

        if(intf_it == sys_ifs.end()) {
            unsigned int sys_if_idx = if_nametoindex(iface_name.c_str());
            if(sys_ifs.size() < sys_if_idx+1) {
                sys_ifs.resize(sys_if_idx+1);
                intf_it = sys_ifs.end() - 1;
            }

            intf_it = sys_ifs.begin() + sys_if_idx;
            intf_it->name  = iface_name;
            intf_it->flags = p_if->ifa_flags;

            struct ifreq ifr;
            strncpy(ifr.ifr_name,p_if->ifa_name,IFNAMSIZ);

            if (ioctl(fd, SIOCGIFMTU, &ifr) < 0 ) {
                ERROR("ioctl: %s",strerror(errno));
                ERROR("setting MTU for this interface to default (1500)");
                intf_it->mtu = 1500;
            }
            else {
                intf_it->mtu = ifr.ifr_mtu;
            }
        }

        DBG("iface='%s';ip='%s';flags=0x%x\n",p_if->ifa_name,host,p_if->ifa_flags);
        intf_it->addrs.push_back(IPAddr(fixIface2IP(host, true),p_if->ifa_addr->sa_family));
    }

    freeifaddrs(ifap);
    close(fd);

    return true;
}

int AmLcConfig::checkSipInterfaces()
{
    std::vector<SIP_info*> infos;
    for(auto& sip_if : sip_ifs) {
        bool bfind = false;
        for(auto& media_if : media_ifs) {
            if(sip_if.default_media_if == media_if.name) {
                bfind = true;
            }
        }

        if(!bfind) {
            ERROR("default media interface for sip interface \'%s\' is absent", sip_if.name.c_str());
            return -1;
        }

        for(auto& info : sip_if.proto_info) {
            for(auto& other_info : infos) {
                if(info->local_ip == other_info->local_ip && info->local_port == other_info->local_port && info->type == other_info->type) {
                    ERROR("duplicate ip %s and port %d in interface \'%s\'", other_info->local_ip.c_str(), other_info->local_port, sip_if.name.c_str());
                    return -1;
                }
            }
        }

        for(auto& info : sip_if.proto_info) {
            infos.push_back(const_cast<SIP_info*>(info));
        }
    }

    return 0;
}

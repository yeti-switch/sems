#include "AmLcConfig.h"
#include <algorithm>
#include <string.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "sip/ip_util.h"
#include "sip/trans_layer.h"
#include "sip/raw_sender.h"
#include "sip/resolver.h"
#include "AmPlugIn.h"
#include "SipCtrlInterface.h"
#include "AmUtils.h"
#include "AmSessionContainer.h"

#define SECTION_SIGIF_NAME           "signaling-interfaces"
#define SECTION_MEDIAIF_NAME         "media-interfaces"
#define SECTION_IF_NAME              "interface"
#define SECTION_IP4_NAME             "ip4"
#define SECTION_IP6_NAME             "ip6"
#define SECTION_RTSP_NAME            "rtsp"
#define SECTION_RTP_NAME             "rtp"
#define SECTION_SIP_TCP_NAME         "sip-tcp"
#define SECTION_SIP_UDP_NAME         "sip-udp"
#define SECTION_OPT_NAME             "options-acl"
#define SECTION_ORIGACL_NAME         "origination-acl"
#define SECTION_MODULES_NAME         "modules"
#define SECTION_MODULE_NAME          "module"
#define SECTION_GENERAL_NAME         "general"
#define SECTION_ROUTING_NAME         "routing"
#define SECTION_APPLICATION_NAME     "application"

#define PARAM_DEFAULT_MEDIAIF_NAME   "default-media-interface"
#define PARAM_ADDRESS_NAME           "address"
#define PARAM_LOW_PORT_NAME          "low-port"
#define PARAM_HIGH_PORT_NAME         "high-port"
#define PARAM_PORT_NAME              "port"
#define PARAM_DSCP_NAME              "dscp"
#define PARAM_USE_RAW_NAME           "use-raw-sockets"
#define PARAM_STAT_CL_PORT_NAME      "static-client-port"
#define PARAM_FORCE_VIA_PORT_NAME    "force-via-address"
#define PARAM_FORCE_OBD_IF_NAME      "force_outbound_if"
#define PARAM_PUBLIC_ADDR_NAME       "public_address"
#define PARAM_CONNECT_TIMEOUT_NAME   "connect-timeout"
#define PARAM_IDLE_TIMEOUT_NAME      "idle-timeout"
#define PARAM_WHITELIST_NAME         "whitelist"
#define PARAM_METHOD_NAME            "method"
#define PARAM_PATH_NAME              "path"
#define PARAM_CPATH_NAME             "config_path"
#define PARAM_GLOBAL_NAME            "global"
#define PARAM_BL_TTL_NAME            "default_bl_ttl"
#define PARAM_LOG_RAW_NAME           "log_raw_messages"
#define PARAM_LOG_PARS_NAME          "log_parsed_messages"
#define PARAM_UDP_RECVBUF_NAME       "udp_rcvbuf"
#define PARAM_DUMP_PATH_NAME         "log_dump_path"
#define PARAM_LOG_LEVEL_NAME         "syslog_loglevel"
#define PARAM_STDERR_NAME            "stderr"
#define PARAM_LOG_STDERR_LEVEL_NAME  "stderr_loglevel"
#define PARAM_SL_FACILITY_NAME       "syslog_facility"
#define PARAM_SESS_PROC_THREADS_NAME "session_processor_threads"
#define PARAM_MEDIA_THREADS_NAME     "media_processor_threads"
#define PARAM_SIP_SERVERS_NAME       "sip_server_threads"
#define PARAM_RTP_RECEIVERS_NAME     "rtp_receiver_threads"
#define PARAM_OUTBOUND_PROXY_NAME    "outbound_proxy"
#define PARAM_FORCE_OUTBOUND_NAME    "force_outbound_proxy"
#define PARAM_FORCE_OUTBOUND_IF_NAME "force_outbound_if"
#define PARAM_FORCE_SYMMETRIC_NAME   "force_symmetric_rtp"
#define PARAM_USE_RAW_SOCK_NAME      "use_raw_sockets"
#define PARAM_DISABLE_DNS_SRV_NAME   "disable_dns_srv"
#define PARAM_DETECT_INBAND_NAME     "detect_inband_dtmf"
#define PARAM_SIP_NAT_HANDLING_NAME  "sip_nat_handling"
#define PARAM_NEXT_HOP_NAME          "next_hop"
#define PARAM_NEXT_HOP_1ST_NAME      "next_hop_1st_req"
#define PARAM_PROXY_STICKY_AUTH_NAME "proxy_sticky_auth"
#define PARAM_NOTIFY_LOWER_CSEQ_NAME "ignore_notify_lower_cseq"
#define PARAM_SLIM_NAME              "session_limit"
#define PARAM_SLIM_ERR_CODE_NAME     "session_limit_err_code"
#define PARAM_SLIM_ERR_REASON_NAME   "session_limit_err_reason"
#define PARAM_OSLIM_NAME             "options_session_limit"
#define PARAM_OSLIM_ERR_CODE_NAME    "options_session_limit_err_code"
#define PARAM_OSLIM_ERR_REASON_NAME  "options_session_limit_err_reason"
#define PARAM_CPSLIMIT_NAME          "cps_limit"
#define PARAM_CPSLIMIT_ERR_CODE_NAME "cps_limit_err_code"
#define PARAM_CPSLIMIT_REASON_NAME   "cps_limit_err_reason"
#define PARAM_SDM_ERR_CODE_NAME      "shutdown_mode_err_code"
#define PARAM_SDM_ERR_REASON_NAME    "shutdown_mode_err_reason"
#define PARAM_SDM_ALLOW_UAC_NAME     "shutdown_mode_allow_uac"
#define PARAM_ENABLE_RTSP_NAME       "enable_rtsp"
#define PARAM_OPT_TRANSCODE_OUT_NAME "options_transcoder_out_stats_hdr"
#define PARAM_OPT_TRANSCODE_IN_NAME  "options_transcoder_in_stats_hdr"
#define PARAM_TRANSCODE_OUT_NAME     "transcoder_out_stats_hdr"
#define PARAM_TRANSCODE_IN_NAME      "transcoder_in_stats_hdr"
#define PARAM_LOG_SESSIONS_NAME      "log_sessions"
#define PARAM_LOG_EVENTS_NAME        "log_events"
#define PARAM_USE_DEF_SIG_NAME       "use_default_signature"
#define PARAM_SIGNATURE_NAME         "signature"
#define PARAM_NODE_ID_NAME           "node_id"
#define PARAM_MAX_FORWARDS_NAME      "max_forwards"
#define PARAM_MAX_SHUTDOWN_TIME_NAME "max_shutdown_time"
#define PARAM_DEAD_RTP_TIME_NAME     "dead_rtp_time"
#define PARAM_DTMF_DETECTOR_NAME     "dtmf_detector"
#define PARAM_SINGLE_CODEC_INOK_NAME "single_codec_in_ok"
#define PARAM_CODEC_ORDER_NAME       "codec_order"
#define PARAM_ACCEPT_FORKED_DLG_NAME "accept_forked_dialogs"
#define PARAM_100REL_NAME            "100rel"
#define PARAM_UNHDL_REP_LOG_LVL_NAME "unhandled_reply_loglevel"
#define PARAM_PCAP_UPLOAD_QUEUE_NAME "pcap_upload_queue"
#define PARAM_RESAMPLE_LIBRARY_NAME  "resampling_library"
#define PARAM_ENABLE_ZRTP_NAME       "enable_zrtp"
#define PARAM_ENABLE_ZRTP_DLOG_NAME  "enable_zrtp_debuglog"
#define PARAM_EXCLUDE_PAYLOADS_NAME  "exclude_payloads"
#define PARAM_DEAMON_NAME            "deamon"
#define PARAM_DEAMON_UID_NAME        "daemon_uid"
#define PARAM_DEAMON_GID_NAME        "daemon_gid"
#define PARAM_SIP_TIMER_NAME         "sip_timer_"
#define PARAM_SIP_TIMER_T2_NAME      PARAM_SIP_TIMER_NAME "t2"
#define PARAM_SIP_TIMER_A_NAME       PARAM_SIP_TIMER_NAME "a"
#define PARAM_SIP_TIMER_B_NAME       PARAM_SIP_TIMER_NAME "b"
#define PARAM_SIP_TIMER_D_NAME       PARAM_SIP_TIMER_NAME "d"
#define PARAM_SIP_TIMER_E_NAME       PARAM_SIP_TIMER_NAME "e"
#define PARAM_SIP_TIMER_F_NAME       PARAM_SIP_TIMER_NAME "f"
#define PARAM_SIP_TIMER_K_NAME       PARAM_SIP_TIMER_NAME "k"
#define PARAM_SIP_TIMER_G_NAME       PARAM_SIP_TIMER_NAME "g"
#define PARAM_SIP_TIMER_H_NAME       PARAM_SIP_TIMER_NAME "h"
#define PARAM_SIP_TIMER_I_NAME       PARAM_SIP_TIMER_NAME "i"
#define PARAM_SIP_TIMER_J_NAME       PARAM_SIP_TIMER_NAME "j"
#define PARAM_SIP_TIMER_L_NAME       PARAM_SIP_TIMER_NAME "l"
#define PARAM_SIP_TIMER_M_NAME       PARAM_SIP_TIMER_NAME "m"
#define PARAM_SIP_TIMER_C_NAME       PARAM_SIP_TIMER_NAME "c"
#define PARAM_SIP_TIMER_BL_NAME      PARAM_SIP_TIMER_NAME "bl"
#define PARAM_APP_REG_NAME           "register_application"
#define PARAM_APP_OPT_NAME           "options_application"
#define PARAM_APP_NAME               "application"

#define VALUE_OFF                    "off"
#define VALUE_ON                     "on"
#define VALUE_YES                    "yes"
#define VALUE_NO                     "no"
#define VALUE_ON                     "on"
#define VALUE_TRUE                   "true"
#define VALUE_FALSE                  "false"
#define VALUE_DROP                   "drop"
#define VALUE_REJECT                 "reject"
#define VALUE_BL_TTL                 60000 /* 60s */
#define VALUE_LOG_NO                 "no"
#define VALUE_LOG_DEBUG              "debug"
#define VALUE_LOG_ERR                "error"
#define VALUE_LOG_WARN               "warn"
#define VALUE_LOG_INFO               "info"
#define VALUE_UDP_RECVBUF            -1
#define VALUE_LOG_DUMP_PATH          "/var/spool/sems/logdump"
#define VALUE_NUM_SESSION_PROCESSORS 10
#define VALUE_NUM_SESSION_PROCESSORS 10
#define VALUE_NUM_MEDIA_PROCESSORS   1
#define VALUE_NUM_RTP_RECEIVERS      1
#define VALUE_NUM_SIP_SERVERS        4
#define VALUE_SESSION_LIMIT          0
#define VALUE_503_ERR_CODE           503
#define VALUE_SESSION_LIMIT_ERR      "Server overload"
#define VALUE_CPSLIMIT_ERR           "Server overload"
#define VALUE_SDM_ERR_REASON         "Server shutting down"
#define VALUE_MAX_SHUTDOWN_TIME      10
#define VALUE_DEAD_RTP_TIME          5*60
#define VALUE_SPANDSP                "spandsp"
#define VALUE_INTERNAL               "internal"
#define VALUE_DISABLE                "disabled"
#define VALUE_SUPPORTED              "supported"
#define VALUE_REQUIRE                "require"
#define VALUE_LIBSAMPLERATE          "libsamplerate"
#define VALUE_UNAVAILABLE            "unavailable"
#define VALUE_RURI_USER              "$(ruri.user)"
#define VALUE_RURI_PARAM             "$(ruri.param)"
#define VALUE_APP_HEADER             "$(apphdr)"
#define VALUE_MAPPING                "$(mapping)"

#define CONF_FILE_PATH               "/etc/sems/sems.cfg"

/*******************************************************************************************************/
/*                                                                                                     */
/*                                       Validation functions                                          */
/*                                                                                                     */
/*******************************************************************************************************/
int validate_on_off_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    bool valid = (value == VALUE_OFF || value == VALUE_ON);
    if(!valid) {
        ERROR("invalid value \'%s\' of option \'%s\' - must be \'on\' or \'off\'", value.c_str(), opt->name);
    }
    return valid ? 0 : 1;
}

int validate_yes_no_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    bool valid = (value == VALUE_YES || value == VALUE_NO);
    if(!valid) {
        ERROR("invalid value \'%s\' of option \'%s\' - must be \'yes\' or \'no\'", value.c_str(), opt->name);
    }
    return valid ? 0 : 1;
}

int validate_bool_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    bool valid = (value == VALUE_TRUE || value == VALUE_FALSE);
    if(!valid) {
        ERROR("invalid value \'%s\' of option \'%s\' - must be \'true\' or \'false\'", value.c_str(), opt->name);
    }
    return valid ? 0 : 1;
}

int parse_log_level(const std::string& level)
{
    int n;
    if (sscanf(level.c_str(), "%i", &n) == 1) {
        if (n < L_ERR || n > L_DBG) {
            return -1;
        }
        return n;
    }

    std::string s(level);
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);

    if (s == VALUE_LOG_ERR) {
        n = L_ERR;
    } else if (s == VALUE_LOG_WARN) {
        n = L_WARN;
    } else if (s == VALUE_LOG_INFO) {
        n = L_INFO;
    } else if (s==VALUE_LOG_DEBUG) {
        n = L_DBG;
    } else {
        fprintf(stderr,"unknown loglevel value: %s",level.c_str());
        return -1;
    }
    return n;
}

int validate_log_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    bool valid = parse_log_level(value) >= 0;
    if(!valid) {
        ERROR("invalid value \'%s\' of option \'%s\' - \
              must be \'no\',\'error\',\'info\',\'warn\',\'debug\' or number from %d to %d",
              value.c_str(), opt->name, L_ERR, L_DBG);
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

int validate_dtmf_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    bool valid = (value == VALUE_SPANDSP || value == VALUE_INTERNAL);
    if(!valid) {
        ERROR("invalid value \'%s\' of option \'%s\' - must be \'spandsp\' or \'internal\'", value.c_str(), opt->name);
    }
    return valid ? 0 : 1;
}

int validate_100rel_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    bool valid = (value == VALUE_DISABLE ||
                  value == VALUE_OFF ||
                  value == VALUE_SUPPORTED ||
                  value == VALUE_REQUIRE);
    if(!valid) {
        ERROR("invalid value \'%s\' of option \'%s\' - must be \'disabled\', \'supported\', \'require\' or \'off\'", value.c_str(), opt->name);
    }
    return valid ? 0 : 1;
}

int validate_resampling_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    bool valid = (value == VALUE_LIBSAMPLERATE ||
                  value == VALUE_UNAVAILABLE ||
                  value == VALUE_INTERNAL);
    if(!valid) {
        ERROR("invalid value \'%s\' of option \'%s\' - must be \'libsamplerate\', \'internal\' or \'unavailable\'", value.c_str(), opt->name);
    }
    return valid ? 0 : 1;
}

/*******************************************************************************************************/
/*                                                                                                     */
/*                                       AmLcConfig class                                              */
/*                                                                                                     */
/*******************************************************************************************************/
AmLcConfig::AmLcConfig()
: config_path(CONF_FILE_PATH)
, plugin_path(PLUG_IN_PATH)
, log_dump_path()
, session_proc_threads(VALUE_NUM_SESSION_PROCESSORS)
, ignore_sig_chld(true)
, ignore_sig_pipe(true)
, shutdown_mode(false)
, dump_level(0)
#ifndef DISABLE_DAEMON_MODE
, deamon_pid_file(DEFAULT_DAEMON_PID_FILE)
#endif
{

/**********************************************************************************************/
/*                                     interfaces section                                     */
/**********************************************************************************************/
    cfg_opt_t acl[]
    {
        CFG_STR_LIST(PARAM_WHITELIST_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(PARAM_METHOD_NAME, "", CFGF_NODEFAULT),
        CFG_END()
    };

    cfg_opt_t rtsp[] =
    {
        CFG_STR(PARAM_ADDRESS_NAME, "", CFGF_NODEFAULT),
        CFG_INT(PARAM_LOW_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_INT(PARAM_HIGH_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(PARAM_PUBLIC_ADDR_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_USE_RAW_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_FORCE_OBD_IF_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_FORCE_VIA_PORT_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_STAT_CL_PORT_NAME, "", CFGF_NONE),
        CFG_INT(PARAM_DSCP_NAME, 0, CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t rtp[] =
    {
        CFG_STR(PARAM_ADDRESS_NAME, "", CFGF_NODEFAULT),
        CFG_INT(PARAM_LOW_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(PARAM_PUBLIC_ADDR_NAME, "", CFGF_NONE),
        CFG_INT(PARAM_HIGH_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(PARAM_USE_RAW_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_FORCE_OBD_IF_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_FORCE_VIA_PORT_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_STAT_CL_PORT_NAME, "", CFGF_NONE),
        CFG_INT(PARAM_DSCP_NAME, 0, CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t sip_tcp[] =
    {
        CFG_STR(PARAM_ADDRESS_NAME, "", CFGF_NODEFAULT),
        CFG_INT(PARAM_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(PARAM_USE_RAW_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_FORCE_OBD_IF_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_FORCE_VIA_PORT_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_STAT_CL_PORT_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_PUBLIC_ADDR_NAME, "", CFGF_NONE),
        CFG_INT(PARAM_DSCP_NAME, 0, CFGF_NONE),
        CFG_INT(PARAM_CONNECT_TIMEOUT_NAME, 0, CFGT_NONE),
        CFG_INT(PARAM_IDLE_TIMEOUT_NAME, 0, CFGT_NONE),
        CFG_END()
    };

    cfg_opt_t sip_udp[] =
    {
        CFG_STR(PARAM_ADDRESS_NAME, "", CFGF_NODEFAULT),
        CFG_INT(PARAM_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(PARAM_USE_RAW_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_FORCE_OBD_IF_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_FORCE_VIA_PORT_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_PUBLIC_ADDR_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_STAT_CL_PORT_NAME, "", CFGF_NONE),
        CFG_INT(PARAM_DSCP_NAME, 0, CFGF_NONE),
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
        CFG_STR(PARAM_DEFAULT_MEDIAIF_NAME, "", CFGF_NONE),
        CFG_SEC(SECTION_IP4_NAME, ip, CFGF_NODEFAULT),
        CFG_SEC(SECTION_IP6_NAME, ip, CFGF_NODEFAULT),
        CFG_END()
    };

    cfg_opt_t interfaces[] =
    {
        CFG_SEC(SECTION_IF_NAME, interface, CFGF_MULTI | CFGF_TITLE),
        CFG_END()
    };

/**********************************************************************************************/
/*                                            modules section                                 */
/**********************************************************************************************/
    cfg_opt_t module[] =
    {
        CFG_STR(PARAM_GLOBAL_NAME, "false", CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t modules[] =
    {
        CFG_STR(PARAM_PATH_NAME, "/usr/lib/sems/plug-in", CFGF_NONE),
        CFG_STR(PARAM_CPATH_NAME, "/etc/sems/etc/", CFGF_NONE),
        CFG_SEC(SECTION_MODULE_NAME, module, CFGF_MULTI | CFGF_TITLE),
        CFG_END()
    };

/**********************************************************************************************/
/*                                            general section                                 */
/**********************************************************************************************/
    cfg_opt_t general[] =
    {
        CFG_INT(PARAM_BL_TTL_NAME, VALUE_BL_TTL, CFGF_NONE),
        CFG_STR(PARAM_LOG_RAW_NAME, VALUE_LOG_DEBUG, CFGF_NONE),
        CFG_STR(PARAM_LOG_PARS_NAME, VALUE_YES, CFGF_NONE),
        CFG_INT(PARAM_UDP_RECVBUF_NAME, VALUE_UDP_RECVBUF, CFGF_NONE),
        CFG_STR(PARAM_DUMP_PATH_NAME, VALUE_LOG_DUMP_PATH, CFGF_NONE),
        CFG_STR(PARAM_LOG_LEVEL_NAME, VALUE_LOG_INFO, CFGF_NONE),
        CFG_STR(PARAM_STDERR_NAME, VALUE_NO, CFGF_NONE),
        CFG_STR(PARAM_LOG_STDERR_LEVEL_NAME, VALUE_LOG_INFO, CFGF_NONE),
        CFG_STR(PARAM_SL_FACILITY_NAME, "", CFGF_NODEFAULT),
        CFG_INT(PARAM_SESS_PROC_THREADS_NAME, VALUE_NUM_SESSION_PROCESSORS, CFGF_NODEFAULT),
        CFG_INT(PARAM_MEDIA_THREADS_NAME, VALUE_NUM_MEDIA_PROCESSORS, CFGF_NONE),
        CFG_INT(PARAM_SIP_SERVERS_NAME, VALUE_NUM_SIP_SERVERS, CFGF_NONE),
        CFG_INT(PARAM_RTP_RECEIVERS_NAME, VALUE_NUM_RTP_RECEIVERS, CFGF_NONE),
        CFG_STR(PARAM_OUTBOUND_PROXY_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_FORCE_OUTBOUND_NAME, VALUE_NO, CFGF_NONE),
        CFG_STR(PARAM_FORCE_OUTBOUND_IF_NAME, VALUE_NO, CFGF_NONE),
        CFG_STR(PARAM_FORCE_SYMMETRIC_NAME, VALUE_NO, CFGF_NONE),
        CFG_STR(PARAM_USE_RAW_SOCK_NAME, VALUE_NO, CFGF_NONE),
        CFG_STR(PARAM_DISABLE_DNS_SRV_NAME, VALUE_NO, CFGF_NONE),
        CFG_STR(PARAM_DETECT_INBAND_NAME, VALUE_NO, CFGF_NONE),
        CFG_STR(PARAM_SIP_NAT_HANDLING_NAME, VALUE_NO, CFGF_NONE),
        CFG_STR(PARAM_NEXT_HOP_NAME, "", CFGF_NODEFAULT),
        CFG_STR(PARAM_NEXT_HOP_1ST_NAME, VALUE_NO, CFGF_NONE),
        CFG_STR(PARAM_PROXY_STICKY_AUTH_NAME, VALUE_NO, CFGF_NONE),
        CFG_STR(PARAM_NOTIFY_LOWER_CSEQ_NAME, VALUE_NO, CFGF_NONE),
        CFG_INT(PARAM_SLIM_NAME, VALUE_SESSION_LIMIT, CFGF_NONE),
        CFG_INT(PARAM_SLIM_ERR_CODE_NAME, VALUE_503_ERR_CODE, CFGF_NONE),
        CFG_STR(PARAM_SLIM_ERR_REASON_NAME, VALUE_SESSION_LIMIT_ERR, CFGF_NONE),
        CFG_INT(PARAM_OSLIM_NAME, VALUE_SESSION_LIMIT, CFGF_NONE),
        CFG_INT(PARAM_OSLIM_ERR_CODE_NAME, VALUE_503_ERR_CODE, CFGF_NONE),
        CFG_STR(PARAM_OSLIM_ERR_REASON_NAME, VALUE_SESSION_LIMIT_ERR, CFGF_NONE),
        CFG_INT(PARAM_SDM_ERR_CODE_NAME, VALUE_503_ERR_CODE, CFGF_NONE),
        CFG_STR(PARAM_SDM_ERR_REASON_NAME, VALUE_SDM_ERR_REASON, CFGF_NONE),
        CFG_STR(PARAM_SDM_ALLOW_UAC_NAME, VALUE_NO, CFGF_NONE),
        CFG_INT(PARAM_CPSLIMIT_NAME, 0, CFGF_NONE),
        CFG_INT(PARAM_CPSLIMIT_ERR_CODE_NAME, VALUE_503_ERR_CODE, CFGF_NONE),
        CFG_STR(PARAM_CPSLIMIT_REASON_NAME, VALUE_CPSLIMIT_ERR, CFGF_NONE),
        CFG_STR(PARAM_ENABLE_RTSP_NAME, VALUE_YES, CFGF_NONE),
        CFG_STR(PARAM_OPT_TRANSCODE_OUT_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_OPT_TRANSCODE_IN_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_TRANSCODE_OUT_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_TRANSCODE_IN_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_LOG_SESSIONS_NAME, VALUE_NO, CFGF_NONE),
        CFG_STR(PARAM_LOG_EVENTS_NAME, VALUE_NO, CFGF_NONE),
        CFG_STR(PARAM_USE_DEF_SIG_NAME, VALUE_NO, CFGF_NODEFAULT),
        CFG_STR(PARAM_SIGNATURE_NAME, DEFAULT_SIGNATURE, CFGF_NONE),
        CFG_INT(PARAM_NODE_ID_NAME, 0, CFGF_NONE),
        CFG_INT(PARAM_MAX_FORWARDS_NAME, 0, CFGF_NONE),
        CFG_INT(PARAM_MAX_SHUTDOWN_TIME_NAME, VALUE_MAX_SHUTDOWN_TIME, CFGF_NONE),
        CFG_INT(PARAM_DEAD_RTP_TIME_NAME, VALUE_DEAD_RTP_TIME, CFGF_NONE),
        CFG_STR(PARAM_DTMF_DETECTOR_NAME, VALUE_SPANDSP, CFGF_NONE),
        CFG_STR(PARAM_SINGLE_CODEC_INOK_NAME, VALUE_NO, CFGF_NONE),
        CFG_STR_LIST(PARAM_CODEC_ORDER_NAME, 0, CFGF_NODEFAULT),
        CFG_STR_LIST(PARAM_EXCLUDE_PAYLOADS_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(PARAM_ACCEPT_FORKED_DLG_NAME, VALUE_NO, CFGF_NONE),
        CFG_STR(PARAM_100REL_NAME, VALUE_SUPPORTED, CFGF_NONE),
        CFG_STR(PARAM_UNHDL_REP_LOG_LVL_NAME, VALUE_LOG_ERR, CFGF_NONE),
        CFG_STR(PARAM_PCAP_UPLOAD_QUEUE_NAME, "", CFGF_NONE),
        CFG_INT(PARAM_SIP_TIMER_A_NAME, DEFAULT_A_TIMER, CFGF_NONE),
        CFG_INT(PARAM_SIP_TIMER_B_NAME, DEFAULT_B_TIMER, CFGF_NONE),
        CFG_INT(PARAM_SIP_TIMER_D_NAME, DEFAULT_D_TIMER, CFGF_NONE),
        CFG_INT(PARAM_SIP_TIMER_E_NAME, DEFAULT_E_TIMER, CFGF_NONE),
        CFG_INT(PARAM_SIP_TIMER_F_NAME, DEFAULT_F_TIMER, CFGF_NONE),
        CFG_INT(PARAM_SIP_TIMER_K_NAME, DEFAULT_K_TIMER, CFGF_NONE),
        CFG_INT(PARAM_SIP_TIMER_G_NAME, DEFAULT_G_TIMER, CFGF_NONE),
        CFG_INT(PARAM_SIP_TIMER_H_NAME, DEFAULT_H_TIMER, CFGF_NONE),
        CFG_INT(PARAM_SIP_TIMER_I_NAME, DEFAULT_I_TIMER, CFGF_NONE),
        CFG_INT(PARAM_SIP_TIMER_J_NAME, DEFAULT_J_TIMER, CFGF_NONE),
        CFG_INT(PARAM_SIP_TIMER_L_NAME, DEFAULT_L_TIMER, CFGF_NONE),
        CFG_INT(PARAM_SIP_TIMER_M_NAME, DEFAULT_M_TIMER, CFGF_NONE),
        CFG_INT(PARAM_SIP_TIMER_C_NAME, DEFAULT_C_TIMER, CFGF_NONE),
        CFG_INT(PARAM_SIP_TIMER_BL_NAME, DEFAULT_BL_TIMER, CFGF_NONE),
        CFG_INT(PARAM_SIP_TIMER_T2_NAME, DEFAULT_T2_TIMER, CFGF_NONE),
#ifdef USE_LIBSAMPLERATE
#ifndef USE_INTERNAL_RESAMPLER
        CFG_STR(PARAM_RESAMPLE_LIBRARY_NAME, VALUE_LIBSAMPLERATE, CFGF_NONE),
#endif
#endif
#ifdef USE_INTERNAL_RESAMPLER
        CFG_STR(PARAM_RESAMPLE_LIBRARY_NAME, VALUE_INTERNAL, CFGF_NONE),
#endif
#ifndef USE_LIBSAMPLERATE
#ifndef USE_INTERNAL_RESAMPLER
        CFG_STR(PARAM_RESAMPLE_LIBRARY_NAME, VALUE_UNAVAILABLE, CFGF_NONE),
#endif
#endif
#ifdef WITH_ZRTP
        CFG_STR(PARAM_ENABLE_ZRTP_NAME, VALUE_YES, CFGF_NONE),
        CFG_STR(PARAM_ENABLE_ZRTP_DLOG_NAME, VALUE_YES, CFGF_NONE),
#endif
#ifndef DISABLE_DAEMON_MODE
        CFG_STR(PARAM_DEAMON_NAME, VALUE_YES, CFGF_NONE),
        CFG_STR(PARAM_DEAMON_UID_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_DEAMON_GID_NAME, "", CFGF_NONE),
#endif /* !DISABLE_DAEMON_MODE */
        CFG_END()
    };
/**********************************************************************************************/
/*                                        routing section                                     */
/**********************************************************************************************/
    cfg_opt_t routing[] =
    {
        CFG_STR(PARAM_APP_REG_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_APP_OPT_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_APP_NAME, "", CFGF_NONE),
        CFG_END()
    };

/**********************************************************************************************/
/*                                         global section                                     */
/**********************************************************************************************/
    cfg_opt_t opt[] =
    {
        CFG_SEC(SECTION_SIGIF_NAME, interfaces, CFGF_NODEFAULT),
        CFG_SEC(SECTION_MEDIAIF_NAME, interfaces, CFGF_NODEFAULT),
        CFG_SEC(SECTION_MODULES_NAME, modules, CFGF_NODEFAULT),
        CFG_SEC(SECTION_GENERAL_NAME, general, CFGF_NODEFAULT),
        CFG_SEC(SECTION_ROUTING_NAME, routing, CFGF_NODEFAULT),
        CFG_END()
    };

    m_cfg = cfg_init(opt, 0);


/**********************************************************************************************/
/*                                         validation set                                     */
/**********************************************************************************************/
    // signaling interfaces validation
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_SIP_TCP_NAME "|" PARAM_USE_RAW_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_SIP_TCP_NAME "|" PARAM_FORCE_OBD_IF_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_SIP_TCP_NAME "|" PARAM_FORCE_VIA_PORT_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_SIP_TCP_NAME "|" PARAM_STAT_CL_PORT_NAME, validate_on_off_func);

    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_SIP_UDP_NAME "|" PARAM_USE_RAW_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_SIP_UDP_NAME "|" PARAM_FORCE_OBD_IF_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_SIP_UDP_NAME "|" PARAM_FORCE_VIA_PORT_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_SIP_UDP_NAME "|" PARAM_STAT_CL_PORT_NAME, validate_on_off_func);

    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_SIP_TCP_NAME "|" PARAM_USE_RAW_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_SIP_TCP_NAME "|" PARAM_FORCE_OBD_IF_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_SIP_TCP_NAME "|" PARAM_FORCE_VIA_PORT_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_SIP_TCP_NAME "|" PARAM_STAT_CL_PORT_NAME, validate_on_off_func);

    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_SIP_UDP_NAME "|" PARAM_USE_RAW_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_SIP_UDP_NAME "|" PARAM_FORCE_OBD_IF_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_SIP_UDP_NAME "|" PARAM_FORCE_VIA_PORT_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_SIP_UDP_NAME "|" PARAM_STAT_CL_PORT_NAME, validate_on_off_func);

    // media interfaces validation
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_RTP_NAME "|" PARAM_USE_RAW_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_RTP_NAME "|" PARAM_FORCE_OBD_IF_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_RTP_NAME "|" PARAM_FORCE_VIA_PORT_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_RTP_NAME "|" PARAM_STAT_CL_PORT_NAME, validate_on_off_func);

    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_RTSP_NAME "|" PARAM_USE_RAW_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_RTSP_NAME "|" PARAM_FORCE_OBD_IF_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_RTSP_NAME "|" PARAM_FORCE_VIA_PORT_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|" SECTION_RTSP_NAME "|" PARAM_STAT_CL_PORT_NAME, validate_on_off_func);

    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_RTP_NAME "|" PARAM_USE_RAW_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_RTP_NAME "|" PARAM_FORCE_OBD_IF_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_RTP_NAME "|" PARAM_FORCE_VIA_PORT_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_RTP_NAME "|" PARAM_STAT_CL_PORT_NAME, validate_on_off_func);

    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_RTSP_NAME "|" PARAM_USE_RAW_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_RTSP_NAME "|" PARAM_FORCE_OBD_IF_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_RTSP_NAME "|" PARAM_FORCE_VIA_PORT_NAME, validate_on_off_func);
    cfg_set_validate_func(m_cfg, SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|" SECTION_RTSP_NAME "|" PARAM_STAT_CL_PORT_NAME, validate_on_off_func);

    // acl of interfaces validation
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|"
                                 SECTION_SIP_UDP_NAME "|" SECTION_OPT_NAME "|" PARAM_METHOD_NAME, validate_method_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|"
                                 SECTION_SIP_UDP_NAME "|" SECTION_OPT_NAME "|" PARAM_METHOD_NAME, validate_method_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|"
                                 SECTION_SIP_TCP_NAME "|" SECTION_OPT_NAME "|" PARAM_METHOD_NAME, validate_method_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|"
                                 SECTION_SIP_TCP_NAME "|" SECTION_OPT_NAME "|" PARAM_METHOD_NAME, validate_method_func);

    // ip of interfaces validation
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|"
                                 SECTION_SIP_TCP_NAME "|" PARAM_ADDRESS_NAME, validate_ip6_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|"
                                 SECTION_SIP_UDP_NAME "|" PARAM_ADDRESS_NAME, validate_ip6_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|"
                                 SECTION_SIP_TCP_NAME "|" PARAM_ADDRESS_NAME, validate_ip4_func);
    cfg_set_validate_func(m_cfg, SECTION_SIGIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|"
                                 SECTION_SIP_UDP_NAME "|" PARAM_ADDRESS_NAME, validate_ip4_func);

    // modules validation
    cfg_set_validate_func(m_cfg, SECTION_MODULES_NAME "|" SECTION_MODULE_NAME "|" PARAM_GLOBAL_NAME , validate_bool_func);

    // general validation
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_LOG_RAW_NAME , validate_log_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_LOG_LEVEL_NAME , validate_log_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_LOG_PARS_NAME , validate_yes_no_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_LOG_STDERR_LEVEL_NAME , validate_log_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_STDERR_NAME , validate_yes_no_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_FORCE_OUTBOUND_NAME , validate_yes_no_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_FORCE_OUTBOUND_IF_NAME , validate_yes_no_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_FORCE_SYMMETRIC_NAME , validate_yes_no_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_USE_RAW_SOCK_NAME , validate_yes_no_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_DISABLE_DNS_SRV_NAME , validate_yes_no_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_DETECT_INBAND_NAME , validate_yes_no_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_SIP_NAT_HANDLING_NAME , validate_yes_no_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_NEXT_HOP_1ST_NAME , validate_yes_no_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_PROXY_STICKY_AUTH_NAME , validate_yes_no_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_NOTIFY_LOWER_CSEQ_NAME , validate_yes_no_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_ENABLE_RTSP_NAME , validate_yes_no_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_LOG_SESSIONS_NAME , validate_yes_no_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_LOG_EVENTS_NAME , validate_yes_no_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_USE_DEF_SIG_NAME , validate_yes_no_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_DTMF_DETECTOR_NAME , validate_dtmf_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_SINGLE_CODEC_INOK_NAME , validate_yes_no_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_ACCEPT_FORKED_DLG_NAME , validate_yes_no_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_100REL_NAME , validate_100rel_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_UNHDL_REP_LOG_LVL_NAME , validate_log_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_RESAMPLE_LIBRARY_NAME , validate_resampling_func);
#ifdef WITH_ZRTP
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_ENABLE_ZRTP_NAME , validate_yes_no_func);
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_ENABLE_ZRTP_DLOG_NAME , validate_yes_no_func);
#endif
#ifndef DISABLE_DAEMON_MODE
    cfg_set_validate_func(m_cfg, SECTION_GENERAL_NAME "|" PARAM_DEAMON_NAME , validate_yes_no_func);
#endif
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

    if(readModules() ||
       readRoutings()||
       readGeneral() ||
       readSigInterfaces() ||
       readMediaInterfaces() ||
       checkSipInterfaces()) {
        return -1;
    }
    return 0;
}

int AmLcConfig::readGeneral()
{
    if(!cfg_size(m_cfg, SECTION_GENERAL_NAME)) {
        ERROR(SECTION_GENERAL_NAME " absent\n");
        return -1;
    }
    cfg_t* gen = cfg_getsec(m_cfg, SECTION_GENERAL_NAME);

    _trans_layer::default_bl_ttl = cfg_getint(gen, PARAM_BL_TTL_NAME);
    trsp_socket::log_level_raw_msgs = parse_log_level(cfg_getstr(gen, PARAM_LOG_RAW_NAME));
    std::string logpars = cfg_getstr(gen, PARAM_LOG_PARS_NAME);
    _SipCtrlInterface::log_parsed_messages = (logpars=="yes");
    _SipCtrlInterface::udp_rcvbuf = cfg_getint(gen, PARAM_UDP_RECVBUF_NAME);
    sip_timer_t2 = cfg_getint(gen, PARAM_SIP_TIMER_T2_NAME);
    for (int t = STIMER_A; t < __STIMER_MAX; t++) {
        std::string timer_cfg = std::string("sip_timer_") + (char)tolower(*timer_name(t));
        sip_timers[t] = cfg_getint(gen, timer_cfg.c_str());
	    DBG("Set SIP Timer '%s' to %u ms\n", timer_name(t), sip_timers[t]);
    }

    log_dump_path = cfg_getstr(gen, PARAM_DUMP_PATH_NAME);
    log_level = (Log_Level)parse_log_level(cfg_getstr(gen, PARAM_LOG_LEVEL_NAME));
    setLogStderr(cfg_getstr(gen, PARAM_STDERR_NAME));
    setStderrLogLevel(cfg_getstr(gen, PARAM_LOG_STDERR_LEVEL_NAME));
#ifndef DISABLE_SYSLOG_LOG
    if (cfg_size(gen, PARAM_SL_FACILITY_NAME)) {
        set_syslog_facility(cfg_getstr(gen, PARAM_SL_FACILITY_NAME));
    }
#endif
    if (cfg_size(gen, PARAM_SESS_PROC_THREADS_NAME)) {
#ifdef SESSION_THREADPOOL
        session_proc_threads = cfg_getint(gen, PARAM_SESS_PROC_THREADS_NAME);
        if (session_proc_threads < 1) {
            ERROR("invalid session_processor_threads value specified."
                  " need at least one thread\n");
            return -1;
        }
#else
        WARN("session_processor_threads specified in sems.conf,\n");
        WARN("but SEMS is compiled without SESSION_THREADPOOL support.\n");
        WARN("set USE_THREADPOOL in Makefile.defs to enable session thread pool.\n");
        WARN("SEMS will start now, but every call will have its own thread.\n");
#endif
    }

    media_proc_threads = cfg_getint(gen, PARAM_MEDIA_THREADS_NAME);
    rtp_recv_threads = cfg_getint(gen, PARAM_RTP_RECEIVERS_NAME);
    sip_server_threads = cfg_getint(gen, PARAM_SIP_SERVERS_NAME);
    outbound_proxy = cfg_getstr(gen, PARAM_OUTBOUND_PROXY_NAME);
    std::string value = cfg_getstr(gen, PARAM_FORCE_OUTBOUND_NAME);
    force_outbound_proxy = (value == VALUE_YES);
    value = cfg_getstr(gen, PARAM_FORCE_OUTBOUND_IF_NAME);
    force_outbound_if = (value == VALUE_YES);
    value = cfg_getstr(gen, PARAM_FORCE_SYMMETRIC_NAME);
    force_symmetric_rtp = (value == VALUE_YES);
    value = cfg_getstr(gen, PARAM_USE_RAW_SOCK_NAME);
    use_raw_sockets = (value == VALUE_YES);
	if(use_raw_sockets && (raw_sender::init() < 0)) {
        use_raw_sockets = false;
	}
    value = cfg_getstr(gen, PARAM_DISABLE_DNS_SRV_NAME);
    _resolver::disable_srv = (value == VALUE_YES);
    value = cfg_getstr(gen, PARAM_DETECT_INBAND_NAME);
    detect_inband_dtmf = (value == VALUE_YES);
    value = cfg_getstr(gen, PARAM_SIP_NAT_HANDLING_NAME);
    sip_nat_handling = (value == VALUE_YES);
    if(cfg_size(gen, PARAM_NEXT_HOP_NAME)) {
        next_hop = cfg_getstr(gen, PARAM_NEXT_HOP_NAME);
        value = cfg_getstr(gen, PARAM_NEXT_HOP_1ST_NAME);
        next_hop_1st_req = (value == VALUE_YES);
    }
    value = cfg_getstr(gen, PARAM_PROXY_STICKY_AUTH_NAME);
    proxy_sticky_auth = (value == VALUE_YES);
    value = cfg_getstr(gen, PARAM_NOTIFY_LOWER_CSEQ_NAME);
    ignore_notify_lower_cseq = (value == VALUE_YES);
    session_limit =  cfg_getint(gen, PARAM_SLIM_NAME);
    session_limit_err_code = cfg_getint(gen, PARAM_SLIM_ERR_CODE_NAME);
    session_limit_err_reason = cfg_getstr(gen, PARAM_SLIM_ERR_REASON_NAME);
    options_session_limit =  cfg_getint(gen, PARAM_OSLIM_NAME);
    options_session_limit_err_code = cfg_getint(gen, PARAM_OSLIM_ERR_CODE_NAME);
    options_session_limit_err_reason = cfg_getstr(gen, PARAM_OSLIM_ERR_REASON_NAME);
    AmSessionContainer::instance()->setCPSLimit(cfg_getint(gen, PARAM_CPSLIMIT_NAME));
    cps_limit_err_code = cfg_getint(gen, PARAM_CPSLIMIT_ERR_CODE_NAME);
    cps_limit_err_reason = cfg_getstr(gen, PARAM_CPSLIMIT_REASON_NAME);
    shutdown_mode_err_code = cfg_getint(gen, PARAM_SDM_ERR_CODE_NAME);
    shutdown_mode_err_reason = cfg_getstr(gen, PARAM_SDM_ERR_REASON_NAME);
    value = cfg_getstr(gen, PARAM_SDM_ALLOW_UAC_NAME);
    shutdown_mode_allow_uac = (value == VALUE_YES);
    value = cfg_getstr(gen, PARAM_ENABLE_RTSP_NAME);
    enable_rtsp = (value == VALUE_YES);
    options_transcoder_out_stats_hdr = cfg_getstr(gen, PARAM_OPT_TRANSCODE_OUT_NAME);
    options_transcoder_in_stats_hdr = cfg_getstr(gen, PARAM_OPT_TRANSCODE_IN_NAME);
    transcoder_out_stats_hdr = cfg_getstr(gen, PARAM_TRANSCODE_OUT_NAME);
    transcoder_in_stats_hdr = cfg_getstr(gen, PARAM_TRANSCODE_IN_NAME);
    value = cfg_getstr(gen, PARAM_LOG_SESSIONS_NAME);
    log_sessions = (value == VALUE_YES);
    value = cfg_getstr(gen, PARAM_LOG_EVENTS_NAME);
    log_events = (value == VALUE_YES);
    if(!cfg_size(gen, PARAM_USE_DEF_SIG_NAME) ||
       strcmp(cfg_getstr(gen, PARAM_USE_DEF_SIG_NAME), VALUE_YES) == 0) {
        signature = DEFAULT_SIGNATURE;
    } else {
        signature = cfg_getstr(gen, PARAM_SIGNATURE_NAME);
    }
    node_id = cfg_getint(gen, PARAM_NODE_ID_NAME);
    if(node_id!=0) node_id_prefix = int2str(node_id) + "-";
    max_forwards = cfg_getint(gen, PARAM_MAX_FORWARDS_NAME);
    max_shutdown_time = cfg_getint(gen, PARAM_MAX_SHUTDOWN_TIME_NAME);
    dead_rtp_time = cfg_getint(gen, PARAM_DEAD_RTP_TIME_NAME);
    value = cfg_getstr(gen, PARAM_DTMF_DETECTOR_NAME);
    if(value == VALUE_SPANDSP) default_dtmf_detector = Dtmf::SpanDSP;
    else default_dtmf_detector = Dtmf::SEMSInternal;
    value = cfg_getstr(gen, PARAM_SINGLE_CODEC_INOK_NAME);
    single_codec_in_ok = (value == VALUE_YES);
    for(size_t i = 0; i < cfg_size(gen, PARAM_CODEC_ORDER_NAME); i++) {
        codec_order.push_back(cfg_getnstr(gen, PARAM_CODEC_ORDER_NAME, i));
    }
    for(size_t i = 0; i < cfg_size(gen, PARAM_EXCLUDE_PAYLOADS_NAME); i++) {
        exclude_payloads.push_back(cfg_getnstr(gen, PARAM_EXCLUDE_PAYLOADS_NAME, i));
    }
    value = cfg_getstr(gen, PARAM_ACCEPT_FORKED_DLG_NAME);
    accept_forked_dialogs = (value == VALUE_NO);
    value = cfg_getstr(gen, PARAM_100REL_NAME);
    if(value == VALUE_DISABLE || value == VALUE_OFF) rel100 = Am100rel::REL100_DISABLED;
    else if(value == VALUE_SUPPORTED) rel100 = Am100rel::REL100_SUPPORTED;
    else if(value == VALUE_REQUIRE) rel100 = Am100rel::REL100_REQUIRE;
    unhandled_reply_log_level = (Log_Level)parse_log_level(cfg_getstr(gen, PARAM_UNHDL_REP_LOG_LVL_NAME));
    pcap_upload_queue_name = cfg_getstr(gen, PARAM_PCAP_UPLOAD_QUEUE_NAME);
    value = cfg_getstr(gen, PARAM_RESAMPLE_LIBRARY_NAME);
    if(value == VALUE_LIBSAMPLERATE) resampling_implementation_type = AmAudio::LIBSAMPLERATE;
    else if(value == VALUE_UNAVAILABLE) resampling_implementation_type = AmAudio::UNAVAILABLE;
    else if(value == VALUE_INTERNAL) resampling_implementation_type = AmAudio::INTERNAL_RESAMPLER;
#ifdef WITH_ZRTP
    value = cfg_getstr(gen, PARAM_ENABLE_ZRTP_NAME);
    enable_zrtp = (value == VALUE_YES);
    value = cfg_getstr(gen, PARAM_ENABLE_ZRTP_DLOG_NAME);
    enable_zrtp_debuglog = (value == VALUE_YES);
#endif
#ifndef DISABLE_DAEMON_MODE
    value = cfg_getstr(gen, PARAM_DEAMON_NAME);
    deamon_mode = (value == VALUE_YES);
    deamon_uid = cfg_getstr(gen, PARAM_DEAMON_UID_NAME);
    deamon_gid = cfg_getstr(gen, PARAM_DEAMON_GID_NAME);
#endif /* !DISABLE_DAEMON_MODE */

    return 0;
}

int AmLcConfig::readRoutings()
{
    if(!cfg_size(m_cfg, SECTION_ROUTING_NAME)) {
        ERROR(SECTION_ROUTING_NAME " absent\n");
        return -1;
    }
    cfg_t* routing = cfg_getsec(m_cfg, SECTION_ROUTING_NAME);

    register_application = cfg_getstr(routing, PARAM_APP_REG_NAME);
    options_application = cfg_getstr(routing, PARAM_APP_OPT_NAME);

    string apps_str = cfg_getstr(routing, PARAM_APP_NAME);
    auto apps = explode(apps_str,"|");
    applications.resize(apps.size());
    int app_selector_id = 0;
    for(const auto &app_str: apps) {
        app_selector &app = applications[app_selector_id];
        app.application = app_str;
        if (app_str == "$(ruri.user)") {
            app.app_select = App_RURIUSER;
        } else if (app_str == "$(ruri.param)") {
            app.app_select = App_RURIPARAM;
        } else if (app_str == "$(apphdr)") {
            app.app_select = App_APPHDR;
        } else if (app_str == "$(mapping)") {
            app.app_select = App_MAPPING;
            string appcfg_fname = AmConfig.configs_path + "app_mapping.conf";
            DBG("Loading application mapping...\n");
            if (!read_regex_mapping(appcfg_fname, "=>", "application mapping",
                app.app_mapping))
            {
                ERROR("reading application mapping\n");
                return -1;
            }
        } else {
            app.app_select = App_SPECIFIED;
        }
        app_selector_id++;
    }
    return 0;
}

int AmLcConfig::readModules()
{
    if(!cfg_size(m_cfg, SECTION_MODULES_NAME)) {
        ERROR(SECTION_MODULES_NAME " absent\n");
        return -1;
    }
    cfg_t* modules_ = cfg_getsec(m_cfg, SECTION_MODULES_NAME);

    modules_path = cfg_getstr(modules_, PARAM_PATH_NAME);
    configs_path = cfg_getstr(modules_, PARAM_CPATH_NAME);
    int mCount = cfg_size(modules_, SECTION_MODULE_NAME);
    for(int i = 0; i < mCount; i++) {
        cfg_t* module = cfg_getnsec(modules_, SECTION_MODULE_NAME, i);
        std::string name = module->title;
        std::string global = cfg_getstr(module, PARAM_GLOBAL_NAME);
        modules.push_back(name);
        if(global == VALUE_TRUE) {
            AmPlugIn::instance()->set_load_rtld_global(name + ".so");
        }
    }

    return 0;
}

int AmLcConfig::readSigInterfaces()
{
    if(!cfg_size(m_cfg, SECTION_SIGIF_NAME)) {
        ERROR(SECTION_SIGIF_NAME " absent\n");
        return -1;
    }
    cfg_t* sigif = cfg_getsec(m_cfg, SECTION_SIGIF_NAME);

    int ifCount = cfg_size(sigif, SECTION_IF_NAME);
    for(int i = 0; i < ifCount; i++) {
        SIP_interface sip_if;
        cfg_t* if_ = cfg_getnsec(sigif, SECTION_IF_NAME, i);
        sip_if.name = if_->title;
        sip_if.default_media_if = cfg_getstr(if_, PARAM_DEFAULT_MEDIAIF_NAME);
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
    return 0;
}

int AmLcConfig::readMediaInterfaces()
{
    cfg_t* mediaif = cfg_getsec(m_cfg, SECTION_MEDIAIF_NAME);
    int ifCount = cfg_size(mediaif, SECTION_IF_NAME);
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
    info->local_ip = cfg_getstr(cfg, PARAM_ADDRESS_NAME);
    if(cfg_size(cfg, PARAM_PUBLIC_ADDR_NAME)) {
        info->public_ip = cfg_getstr(cfg, PARAM_PUBLIC_ADDR_NAME);
    }
    if(cfg_size(cfg, PARAM_USE_RAW_NAME)) {
        std::string value = cfg_getstr(cfg, PARAM_USE_RAW_NAME);
        if(value == VALUE_ON) {
            info->sig_sock_opts |= trsp_socket::use_raw_sockets;
        }
    }
    if(cfg_size(cfg, PARAM_FORCE_VIA_PORT_NAME)) {
        std::string value = cfg_getstr(cfg, PARAM_FORCE_VIA_PORT_NAME);
        if(value == VALUE_ON) {
            info->sig_sock_opts |= trsp_socket::force_via_address;
        }
    }
    if(cfg_size(cfg, PARAM_STAT_CL_PORT_NAME)) {
        std::string value = cfg_getstr(cfg, PARAM_STAT_CL_PORT_NAME);
        if(value == VALUE_ON) {
            info->sig_sock_opts |= trsp_socket::static_client_port;
        }
    }
    if(cfg_size(cfg, PARAM_FORCE_OBD_IF_NAME)) {
        std::string value = cfg_getstr(cfg, PARAM_FORCE_OBD_IF_NAME);
        if(value == VALUE_ON) {
            info->sig_sock_opts |= trsp_socket::force_outbound_if;
        }
    }
    if(cfg_size(cfg, PARAM_DSCP_NAME)) {
        info->dscp = cfg_getint(cfg, PARAM_DSCP_NAME);
        info->tos_byte = info->dscp << 2;
    }

    if(sinfo) {
        sinfo->local_port = cfg_getint(cfg, PARAM_PORT_NAME);
    }
    if(mediainfo) {
        mediainfo->high_port = cfg_getint(cfg, PARAM_HIGH_PORT_NAME);
        mediainfo->low_port = cfg_getint(cfg, PARAM_LOW_PORT_NAME);
    }

    if(stinfo && cfg_size(cfg, PARAM_CONNECT_TIMEOUT_NAME)) {
        stinfo->tcp_connect_timeout = cfg_getint(cfg, PARAM_CONNECT_TIMEOUT_NAME);
    }

    if(stinfo && cfg_size(cfg, PARAM_IDLE_TIMEOUT_NAME)) {
        stinfo->tcp_idle_timeout = cfg_getint(cfg, PARAM_IDLE_TIMEOUT_NAME);
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
    for(unsigned int j = 0; j < cfg_size(cfg, PARAM_WHITELIST_NAME); j++) {
        AmSubnet net;
        std::string host = cfg_getnstr(cfg, PARAM_WHITELIST_NAME, j);
        if(!net.parse(host)) {
            return 1;
        }
        acl.add_network(net);
        networks++;
    }

    DBG("parsed %d networks from key %s",networks,if_name.c_str());

    std::string method = cfg_getstr(cfg, PARAM_METHOD_NAME);
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

int AmLcConfig::setLogLevel(const std::string& level, bool apply)
{
    int n;
    if(-1==(n = parse_log_level(level))) return 0;
    log_level = (Log_Level)n;
    if (apply)
        set_log_level(log_level);
    return 1;
}

int AmLcConfig::setStderrLogLevel(const std::string& level, bool apply)
{
    int n;
    if(-1==(n = parse_log_level(level))) return 0;
    log_level = (Log_Level)n;
    if (apply && log_stderr)
        set_stderr_log_level(log_level);
    return 1;
}

int AmLcConfig::setLogStderr(const std::string& s, bool apply)
{
  if (s == VALUE_YES) {
    if(apply && !log_stderr)
      register_stderr_facility();
    log_stderr = true;
  } else if (s == VALUE_NO) {
    //deny to disable previously enabled stderr logging
  } else {
    return 0;
  }
  return 1;
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

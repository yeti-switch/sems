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
#include "RtspClient.h"

#include <fstream>
#include <iostream>

#define SECTION_SIGIF_NAME           "signaling-interfaces"
#define SECTION_MEDIAIF_NAME         "media-interfaces"
#define SECTION_IF_NAME              "interface"
#define SECTION_IP4_NAME             "ip4"
#define SECTION_IP6_NAME             "ip6"
#define SECTION_RTSP_NAME            "rtsp"
#define SECTION_RTP_NAME             "rtp"
#define SECTION_SIP_WS_NAME          "sip-ws"
#define SECTION_SIP_WSS_NAME         "sip-wss"
#define SECTION_SIP_TLS_NAME         "sip-tls"
#define SECTION_SIP_TCP_NAME         "sip-tcp"
#define SECTION_SIP_UDP_NAME         "sip-udp"
#define SECTION_OPT_NAME             "options-acl"
#define SECTION_ORIGACL_NAME         "origination-acl"
#define SECTION_REG_ACL_NAME         "register-acl"
#define SECTION_MODULES_NAME         "modules"
#define SECTION_MODULE_NAME          "module"
#define SECTION_MODULE_GLOBAL_NAME   "module-global"
#define SECTION_GENERAL_NAME         "general"
#define SECTION_ROUTING_NAME         "routing"
#define SECTION_APPLICATION_NAME     "application"
#define SECTION_SESSION_LIMIT_NAME   "session_limit"
#define SECTION_OSLIM_NAME           "options_session_limit"
#define SECTION_CPS_LIMIT_NAME       "cps_limit"
#define SECCTION_SDM_NAME            "shutdown_mode"
#define SECTION_SERVER_NAME          "server"
#define SECTION_CLIENT_NAME          "client"
#define SECTION_SRTP_NAME            "srtp"
#define SECTION_SDES_NAME            "sdes"
#define SECTION_DTLS_NAME            "dtls"
#define SECTION_ZRTP_NAME            "zrtp"
#define SECTION_ICE_CAND_FILTER_NAME "ice_candidate_filter"

#define FUNCTION_ALLOW_NAME          "allow"
#define FUNCTION_DENY_NAME           "deny"

#define PARAM_LIMIT_NAME             "limit"
#define PARAM_CODE_NAME              "code"
#define PARAM_REASON_NAME            "reason"
#define PARAM_ALLOW_UAC_NAME         "allow_uac"

#define PARAM_DEFAULT_MEDIAIF_NAME   "default-media-interface"
#define PARAM_ADDRESS_NAME           "address"
#define PARAM_ADDITIONAL_ADDR_NAME   "additional_addresses"
#define PARAM_LOW_PORT_NAME          "low-port"
#define PARAM_HIGH_PORT_NAME         "high-port"
#define PARAM_PORT_NAME              "port"
#define PARAM_DSCP_NAME              "dscp"
#define PARAM_USE_RAW_NAME           "use-raw-sockets"
#define PARAM_STAT_CL_PORT_NAME      "static-client-port"
#define PARAM_FORCE_VIA_PORT_NAME    "force-via-address"
#define PARAM_FORCE_OBD_IF_NAME      "force_outbound_if"
#define PARAM_FORCE_TRANSPORT_NAME   "force-contact-transport"
#define PARAM_PUBLIC_ADDR_NAME       "public-address"
#define PARAM_PUBLIC_DOMAIN_NAME     "domain"
#define PARAM_ANNOUNCE_PORT_NAME     "announce-port"
#define PARAM_CONNECT_TIMEOUT_NAME   "connect-timeout"
#define PARAM_IDLE_TIMEOUT_NAME      "idle-timeout"
#define PARAM_CORS_MODE_NAME         "cors_mode"
#define PARAM_WHITELIST_NAME         "whitelist"
#define PARAM_METHOD_NAME            "method"
#define PARAM_PATH_NAME              "path"
#define PARAM_CPATH_NAME             "config_path"
#define PARAM_BL_TTL_NAME            "default_bl_ttl"
#define PARAM_LOG_RAW_NAME           "log_raw_messages"
#define PARAM_LOG_PARS_NAME          "log_parsed_messages"
#define PARAM_UDP_RECVBUF_NAME       "udp_rcvbuf"
#define PARAM_DUMP_PATH_NAME         "log_dump_path"
#define PARAM_RSR_PATH_NAME          "rsr_path"
#define PARAM_LOG_LEVEL_NAME         "syslog_loglevel"
#define PARAM_STDERR_NAME            "stderr"
#define PARAM_LOG_STDERR_LEVEL_NAME  "stderr_loglevel"
#define PARAM_SL_FACILITY_NAME       "syslog_facility"
#define PARAM_SESS_PROC_THREADS_NAME "session_processor_threads"
#define PARAM_MEDIA_THREADS_NAME     "media_processor_threads"
#define PARAM_SIP_UDP_SERVERS_NAME   "sip_udp_server_threads"
#define PARAM_SIP_TCP_SERVERS_NAME   "sip_tcp_server_threads"
#define PARAM_RTP_RECEIVERS_NAME     "rtp_receiver_threads"
#define PARAM_OUTBOUND_PROXY_NAME    "outbound_proxy"
#define PARAM_FORCE_OUTBOUND_NAME    "force_outbound_proxy"
#define PARAM_FORCE_OUTBOUND_IF_NAME "force_outbound_if"
#define PARAM_FORCE_CANCEL_ROUTE_SET "force_cancel_route_set"
#define PARAM_FORCE_SYMM_RTP_NAME    "force_symmetric_rtp"
#define PARAM_FORCE_SYMM_PAIR_NAME   "force_symmetric_candidate"
#define PARAM_USE_RAW_SOCK_NAME      "use_raw_sockets"
#define PARAM_DISABLE_DNS_SRV_NAME   "disable_dns_srv"
#define PARAM_DETECT_INBAND_NAME     "detect_inband_dtmf"
#define PARAM_SIP_NAT_HANDLING_NAME  "sip_nat_handling"
#define PARAM_NEXT_HOP_NAME          "next_hop"
#define PARAM_NEXT_HOP_1ST_NAME      "next_hop_1st_req"
#define PARAM_PROXY_STICKY_AUTH_NAME "proxy_sticky_auth"
#define PARAM_NOTIFY_LOWER_CSEQ_NAME "ignore_notify_lower_cseq"
#define PARAM_ENABLE_RTSP_NAME       "enable_rtsp"
#define PARAM_ENABLE_SRTP_NAME       "enable_srtp"
#define PARAM_ENABLE_ICE_NAME        "enable_ice"
#define PARAM_OPT_TRANSCODE_OUT_NAME "options_transcoder_out_stats_hdr"
#define PARAM_OPT_TRANSCODE_IN_NAME  "options_transcoder_in_stats_hdr"
#define PARAM_TRANSCODE_OUT_NAME     "transcoder_out_stats_hdr"
#define PARAM_TRANSCODE_IN_NAME      "transcoder_in_stats_hdr"
#define PARAM_LOG_SESSIONS_NAME      "log_sessions"
#define PARAM_LOG_EVENTS_NAME        "log_events"
#define PARAM_SIGNATURE_NAME         "signature"
#define PARAM_SDP_ORIGIN_NAME        "sdp_origin"
#define PARAM_SDP_SESSION_NAME       "sdp_session_name"
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
#define PARAM_EXCLUDE_PAYLOADS_NAME  "exclude_payloads"
#define PARAM_DEAMON_NAME            "daemon"
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
#define PARAM_PROTOCOLS_NAME         "protocols"
#define PARAM_CERTIFICATE_NAME       "certificate"
#define PARAM_CERTIFICATE_KEY_NAME   "certificate_key"
#define PARAM_VERIFY_CERT_NAME       "verify_client_certificate"
#define PARAM_REQUIRE_CERT_NAME      "require_client_certificate"
#define PARAM_CA_LIST_NAME           "ca_list"
#define PARAM_CIPHERS_NAME           "ciphers"
#define PARAM_HASHES_NAME            "hashes"
#define PARAM_AUTHTAGS_NAME          "authtags"
#define PARAM_DHMODES_NAME           "dhmodes"
#define PARAM_SAS_NAME               "sas"
#define PARAM_MACS_NAME              "macs"
#define PARAM_DH_PARAM_NAME          "dhparam"
#define PARAM_CERT_CHAIN_NAME        "verify_certificate_chain"
#define PARAM_CERT_CN_NAME           "verify_certificate_cn"
#define PARAM_PROFILES_NAME          "profiles"
#define PARAM_DTMF_OFFER_MRATE_NAME  "dtmf_offer_multirate"
#define PARAM_DTMF_DEFAULT_VOLUME    "dtmf_default_volume"
#define PARAM_SYMMETRIC_MODE_NAME    "symmetric_rtp_mode"
#define PARAM_SYMMETRIC_PACKETS_NAME "symmetric_rtp_packets"
#define PARAM_SYMMETRIC_DELAY_NAME   "symmetric_rtp_delay"
#define PARAM_TLS_SSL_KEY_LOG_FILE   "ssl_key_log_file"

#define VALUE_OFF                    "off"
#define VALUE_DROP                   "drop"
#define VALUE_REJECT                 "reject"
#define VALUE_BL_TTL                 60000 /* 60s */
#define VALUE_UDP_RECVBUF            -1
#define VALUE_LOG_DUMP_PATH          "/var/spool/sems/logdump"
#define VALUE_RSR_PATH               "/var/spool/sems/rsr/"
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
#define VALUE_PACKETS                "packets"
#define VALUE_DELAY                  "delay"
#define VALUE_SYMMETRIC_RTP_DELAY    250

#define CONF_FILE_PATH               "/etc/sems/sems.conf"

#define WITH_SECTION(SECTION_NAME) if(cfg_t *s = cfg_getsec(gen, SECTION_NAME))

#define cuint(expr) static_cast<unsigned int>(expr)
#define cint(expr) static_cast<int>(expr)

static int ice_candidate_allow(cfg_t *cfg, cfg_opt_t *opt, int argc, const char **argv);
static int ice_candidate_deny(cfg_t *cfg, cfg_opt_t *opt, int argc, const char **argv);

/*******************************************************************************************************/
/*                                                                                                     */
/*                                    configuration options                                            */
/*                                                                                                     */
/*******************************************************************************************************/
namespace Config {

/**********************************************************************************************/
/*                                     interfaces section                                     */
/**********************************************************************************************/
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"

    static cfg_opt_t acl[]
    {
        CFG_STR_LIST(PARAM_WHITELIST_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(PARAM_METHOD_NAME, "", CFGF_NODEFAULT),
        CFG_END()
    };

    static cfg_opt_t rtsp[] =
    {
        CFG_STR(PARAM_ADDRESS_NAME, "", CFGF_NODEFAULT),
        CFG_INT(PARAM_LOW_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_INT(PARAM_HIGH_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(PARAM_PUBLIC_ADDR_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_PUBLIC_DOMAIN_NAME, "", CFGF_NONE),
        CFG_BOOL(PARAM_USE_RAW_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_OBD_IF_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_VIA_PORT_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_STAT_CL_PORT_NAME, cfg_false, CFGF_NONE),
        CFG_INT(PARAM_DSCP_NAME, 0, CFGF_NONE),
        CFG_END()
    };

    static cfg_opt_t dtls_client[] =
    {
        CFG_STR_LIST(PARAM_PROTOCOLS_NAME, 0, CFGF_NODEFAULT),
        CFG_STR_LIST(PARAM_PROFILES_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(PARAM_CERTIFICATE_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_CERTIFICATE_KEY_NAME, "", CFGF_NONE),
        CFG_BOOL(PARAM_CERT_CHAIN_NAME, cfg_true, CFGF_NONE),
        CFG_BOOL(PARAM_CERT_CN_NAME, cfg_true, CFGF_NONE),
        CFG_STR_LIST(PARAM_CA_LIST_NAME, 0, CFGF_NODEFAULT),
        CFG_END()
    };

    static cfg_opt_t dtls_server[] =
    {
        CFG_STR_LIST(PARAM_PROTOCOLS_NAME, 0, CFGF_NODEFAULT),
        CFG_STR_LIST(PARAM_PROFILES_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(PARAM_CERTIFICATE_NAME, "", CFGF_NODEFAULT),
        CFG_STR(PARAM_CERTIFICATE_KEY_NAME, "", CFGF_NODEFAULT),
        CFG_BOOL(PARAM_VERIFY_CERT_NAME, cfg_true, CFGF_NONE),
        CFG_STR_LIST(PARAM_CIPHERS_NAME, 0, CFGF_NODEFAULT),
        CFG_STR_LIST(PARAM_MACS_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(PARAM_DH_PARAM_NAME, "", CFGF_NONE),
        CFG_STR_LIST(PARAM_CA_LIST_NAME, 0, CFGF_NODEFAULT),
        CFG_END()
    };

    static cfg_opt_t dtls[] =
    {
        CFG_SEC(SECTION_CLIENT_NAME, dtls_client, CFGF_NODEFAULT),
        CFG_SEC(SECTION_SERVER_NAME, dtls_server, CFGF_NODEFAULT),
        CFG_END()
    };

    static cfg_opt_t sdes[] =
    {
        CFG_STR_LIST(PARAM_PROFILES_NAME, 0, CFGF_NODEFAULT),
        CFG_END()
    };

    static cfg_opt_t zrtp[] =
    {
        CFG_STR_LIST(PARAM_HASHES_NAME, 0, CFGF_NODEFAULT),
        CFG_STR_LIST(PARAM_CIPHERS_NAME, 0, CFGF_NODEFAULT),
        CFG_STR_LIST(PARAM_AUTHTAGS_NAME, 0, CFGF_NODEFAULT),
        CFG_STR_LIST(PARAM_DHMODES_NAME, 0, CFGF_NODEFAULT),
        CFG_STR_LIST(PARAM_SAS_NAME, 0, CFGF_NODEFAULT),
        CFG_END()
    };

    static cfg_opt_t srtp[] =
    {
        CFG_BOOL(PARAM_ENABLE_SRTP_NAME, cfg_true, CFGF_NONE),
        CFG_SEC(SECTION_SDES_NAME, sdes, CFGF_NONE),
        CFG_SEC(SECTION_DTLS_NAME, dtls, CFGF_NODEFAULT),
        CFG_SEC(SECTION_ZRTP_NAME, zrtp, CFGF_NODEFAULT),
        CFG_END()
    };

    static cfg_opt_t rtp[] =
    {
        CFG_STR(PARAM_ADDRESS_NAME, "", CFGF_NODEFAULT),
        CFG_STR_LIST(PARAM_ADDITIONAL_ADDR_NAME, 0, CFGF_NONE),
        CFG_INT(PARAM_LOW_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(PARAM_PUBLIC_ADDR_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_PUBLIC_DOMAIN_NAME, "", CFGF_NONE),
        CFG_INT(PARAM_HIGH_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_BOOL(PARAM_USE_RAW_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_OBD_IF_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_VIA_PORT_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_STAT_CL_PORT_NAME, cfg_false, CFGF_NONE),
        CFG_INT(PARAM_DSCP_NAME, 0, CFGF_NONE),
        CFG_END()
    };

    static cfg_opt_t sip_tcp[] =
    {
        CFG_STR(PARAM_ADDRESS_NAME, "", CFGF_NODEFAULT),
        CFG_INT(PARAM_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_BOOL(PARAM_USE_RAW_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_OBD_IF_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_TRANSPORT_NAME, cfg_true, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_VIA_PORT_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_STAT_CL_PORT_NAME, cfg_false, CFGF_NONE),
        CFG_STR(PARAM_PUBLIC_ADDR_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_PUBLIC_DOMAIN_NAME, "", CFGF_NONE),
        CFG_BOOL(PARAM_ANNOUNCE_PORT_NAME, cfg_true, CFGF_NONE),
        CFG_INT(PARAM_DSCP_NAME, 0, CFGF_NONE),
        CFG_INT(PARAM_CONNECT_TIMEOUT_NAME, 0, CFGT_NONE),
        CFG_INT(PARAM_IDLE_TIMEOUT_NAME, 0, CFGT_NONE),
        CFG_SEC(SECTION_OPT_NAME, acl, CFGF_NODEFAULT),
        CFG_SEC(SECTION_ORIGACL_NAME, acl, CFGF_NODEFAULT),
        CFG_SEC(SECTION_REG_ACL_NAME, acl, CFGF_NODEFAULT),
        CFG_END()
    };

    static cfg_opt_t sip_udp[] =
    {
        CFG_STR(PARAM_ADDRESS_NAME, "", CFGF_NODEFAULT),
        CFG_INT(PARAM_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_BOOL(PARAM_USE_RAW_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_OBD_IF_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_VIA_PORT_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_TRANSPORT_NAME, cfg_true, CFGF_NONE),
        CFG_BOOL(PARAM_STAT_CL_PORT_NAME, cfg_false, CFGF_NONE),
        CFG_STR(PARAM_PUBLIC_ADDR_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_PUBLIC_DOMAIN_NAME, "", CFGF_NONE),
        CFG_BOOL(PARAM_ANNOUNCE_PORT_NAME, cfg_true, CFGF_NONE),
        CFG_INT(PARAM_DSCP_NAME, 0, CFGF_NONE),
        CFG_SEC(SECTION_OPT_NAME, acl, CFGF_NODEFAULT),
        CFG_SEC(SECTION_ORIGACL_NAME, acl, CFGF_NODEFAULT),
        CFG_SEC(SECTION_REG_ACL_NAME, acl, CFGF_NODEFAULT),
        CFG_END()
    };

    static cfg_opt_t tls_client[] =
    {
        CFG_STR_LIST(PARAM_PROTOCOLS_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(PARAM_CERTIFICATE_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_CERTIFICATE_KEY_NAME, "", CFGF_NONE),
        CFG_BOOL(PARAM_CERT_CHAIN_NAME, cfg_true, CFGF_NONE),
        CFG_BOOL(PARAM_CERT_CN_NAME, cfg_true, CFGF_NONE),
        CFG_STR_LIST(PARAM_CA_LIST_NAME, 0, CFGF_NODEFAULT),
        CFG_END()
    };

    static cfg_opt_t tls_server[] =
    {
        CFG_STR_LIST(PARAM_PROTOCOLS_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(PARAM_CERTIFICATE_NAME, "", CFGF_NODEFAULT),
        CFG_STR(PARAM_CERTIFICATE_KEY_NAME, "", CFGF_NODEFAULT),
        CFG_BOOL(PARAM_VERIFY_CERT_NAME, cfg_true, CFGF_NONE),
        CFG_BOOL(PARAM_REQUIRE_CERT_NAME, cfg_true, CFGF_NONE),
        CFG_STR_LIST(PARAM_CIPHERS_NAME, 0, CFGF_NODEFAULT),
        CFG_STR_LIST(PARAM_MACS_NAME, 0, CFGF_NODEFAULT),
        CFG_STR(PARAM_DH_PARAM_NAME, "", CFGF_NONE),
        CFG_STR_LIST(PARAM_CA_LIST_NAME, 0, CFGF_NODEFAULT),
        CFG_END()
    };

    static cfg_opt_t sip_tls[] =
    {
        CFG_STR(PARAM_ADDRESS_NAME, "", CFGF_NODEFAULT),
        CFG_INT(PARAM_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_BOOL(PARAM_USE_RAW_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_OBD_IF_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_VIA_PORT_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_STAT_CL_PORT_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_TRANSPORT_NAME, cfg_true, CFGF_NONE),
        CFG_STR(PARAM_PUBLIC_ADDR_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_PUBLIC_DOMAIN_NAME, "", CFGF_NONE),
        CFG_BOOL(PARAM_ANNOUNCE_PORT_NAME, cfg_true, CFGF_NONE),
        CFG_INT(PARAM_DSCP_NAME, 0, CFGF_NONE),
        CFG_INT(PARAM_CONNECT_TIMEOUT_NAME, 0, CFGT_NONE),
        CFG_INT(PARAM_IDLE_TIMEOUT_NAME, 0, CFGT_NONE),
        CFG_SEC(SECTION_OPT_NAME, acl, CFGF_NODEFAULT),
        CFG_SEC(SECTION_ORIGACL_NAME, acl, CFGF_NODEFAULT),
        CFG_SEC(SECTION_REG_ACL_NAME, acl, CFGF_NODEFAULT),
        CFG_SEC(SECTION_SERVER_NAME, tls_server, CFGF_NODEFAULT),
        CFG_SEC(SECTION_CLIENT_NAME, tls_client, CFGF_NODEFAULT),
        CFG_END()
    };

    static cfg_opt_t sip_wss[] =
    {
        CFG_STR(PARAM_ADDRESS_NAME, "", CFGF_NODEFAULT),
        CFG_INT(PARAM_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_BOOL(PARAM_USE_RAW_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_OBD_IF_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_VIA_PORT_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_STAT_CL_PORT_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_TRANSPORT_NAME, cfg_true, CFGF_NONE),
        CFG_STR(PARAM_PUBLIC_ADDR_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_PUBLIC_DOMAIN_NAME, "", CFGF_NONE),
        CFG_BOOL(PARAM_ANNOUNCE_PORT_NAME, cfg_true, CFGF_NONE),
        CFG_INT(PARAM_DSCP_NAME, 0, CFGF_NONE),
        CFG_INT(PARAM_CONNECT_TIMEOUT_NAME, 0, CFGT_NONE),
        CFG_INT(PARAM_IDLE_TIMEOUT_NAME, 0, CFGT_NONE),
        CFG_SEC(SECTION_OPT_NAME, acl, CFGF_NODEFAULT),
        CFG_SEC(SECTION_ORIGACL_NAME, acl, CFGF_NODEFAULT),
        CFG_SEC(SECTION_REG_ACL_NAME, acl, CFGF_NODEFAULT),
        CFG_SEC(SECTION_SERVER_NAME, tls_server, CFGF_NODEFAULT),
        CFG_SEC(SECTION_CLIENT_NAME, tls_client, CFGF_NODEFAULT),
        CFG_BOOL(PARAM_CORS_MODE_NAME, cfg_false, CFGF_NODEFAULT),
        CFG_END()
    };

    static cfg_opt_t sip_ws[] =
    {
        CFG_STR(PARAM_ADDRESS_NAME, "", CFGF_NODEFAULT),
        CFG_INT(PARAM_PORT_NAME, 0, CFGF_NODEFAULT),
        CFG_BOOL(PARAM_USE_RAW_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_OBD_IF_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_TRANSPORT_NAME, cfg_true, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_VIA_PORT_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_STAT_CL_PORT_NAME, cfg_false, CFGF_NONE),
        CFG_STR(PARAM_PUBLIC_ADDR_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_PUBLIC_DOMAIN_NAME, "", CFGF_NONE),
        CFG_BOOL(PARAM_ANNOUNCE_PORT_NAME, cfg_true, CFGF_NONE),
        CFG_INT(PARAM_DSCP_NAME, 0, CFGF_NONE),
        CFG_INT(PARAM_CONNECT_TIMEOUT_NAME, 0, CFGT_NONE),
        CFG_INT(PARAM_IDLE_TIMEOUT_NAME, 0, CFGT_NONE),
        CFG_SEC(SECTION_OPT_NAME, acl, CFGF_NODEFAULT),
        CFG_SEC(SECTION_ORIGACL_NAME, acl, CFGF_NODEFAULT),
        CFG_SEC(SECTION_REG_ACL_NAME, acl, CFGF_NODEFAULT),
        CFG_BOOL(PARAM_CORS_MODE_NAME, cfg_false, CFGF_NODEFAULT),
        CFG_END()
    };

    static cfg_opt_t ip[] =
    {
        CFG_SEC(SECTION_RTSP_NAME, rtsp, CFGF_NODEFAULT),
        CFG_SEC(SECTION_RTP_NAME, rtp, CFGF_NODEFAULT),
        CFG_SEC(SECTION_SIP_TCP_NAME, sip_tcp, CFGF_NODEFAULT),
        CFG_SEC(SECTION_SIP_UDP_NAME, sip_udp, CFGF_NODEFAULT),
        CFG_SEC(SECTION_SIP_TLS_NAME, sip_tls, CFGF_NODEFAULT),
        CFG_SEC(SECTION_SIP_WS_NAME, sip_ws, CFGF_NODEFAULT),
        CFG_SEC(SECTION_SIP_WSS_NAME, sip_wss, CFGF_NODEFAULT),
        CFG_END()
    };

    static cfg_opt_t interface[] =
    {
        CFG_FUNC("include", &cfg_include),
        CFG_STR(PARAM_DEFAULT_MEDIAIF_NAME, "", CFGF_NONE),
        CFG_SEC(SECTION_IP4_NAME, ip, CFGF_NODEFAULT),
        CFG_SEC(SECTION_IP6_NAME, ip, CFGF_NODEFAULT),
        CFG_END()
    };

    static cfg_opt_t interfaces[] =
    {
        CFG_FUNC("include", &cfg_include),
        CFG_SEC(SECTION_IF_NAME, interface, CFGF_MULTI | CFGF_TITLE),
        CFG_END()
    };

    static cfg_opt_t media_interface[] =
    {
        CFG_FUNC("include", &cfg_include),
        CFG_SEC(SECTION_IP4_NAME, ip, CFGF_NODEFAULT),
        CFG_SEC(SECTION_IP6_NAME, ip, CFGF_NODEFAULT),
        CFG_SEC(SECTION_SRTP_NAME, srtp, CFGF_NODEFAULT),
        CFG_END()
    };

    static cfg_opt_t media_interfaces[] =
    {
        CFG_FUNC("include", &cfg_include),
        CFG_SEC(SECTION_IF_NAME, media_interface, CFGF_MULTI | CFGF_TITLE),
        CFG_END()
    };

/**********************************************************************************************/
/*                                            modules section                                 */
/**********************************************************************************************/
    static cfg_opt_t module[] =
    {
        CFG_FUNC("include", &cfg_include),
        CFG_END()
    };

    static cfg_opt_t modules[] =
    {
        CFG_FUNC("include", &cfg_include),
        CFG_STR(PARAM_PATH_NAME, "/usr/lib/sems/plug-in", CFGF_NONE),
        CFG_STR(PARAM_CPATH_NAME, "/etc/sems/etc/", CFGF_NONE),
        CFG_SEC(SECTION_MODULE_NAME, module, CFGF_MULTI | CFGF_TITLE | CFGF_RAW | CFGF_IGNORE_UNKNOWN),
        CFG_SEC(SECTION_MODULE_GLOBAL_NAME, module, CFGF_MULTI | CFGF_TITLE | CFGF_RAW | CFGF_IGNORE_UNKNOWN),
        CFG_END()
    };

/**********************************************************************************************/
/*                                            general section                                 */
/**********************************************************************************************/
    static cfg_opt_t slimit[] {
        CFG_INT(PARAM_LIMIT_NAME, VALUE_SESSION_LIMIT, CFGF_NONE),
        CFG_INT(PARAM_CODE_NAME, VALUE_503_ERR_CODE, CFGF_NONE),
        CFG_STR(PARAM_REASON_NAME, VALUE_SESSION_LIMIT_ERR, CFGF_NONE),
        CFG_END()
    };

    static cfg_opt_t options_slimit[] {
        CFG_INT(PARAM_LIMIT_NAME, VALUE_SESSION_LIMIT, CFGF_NONE),
        CFG_INT(PARAM_CODE_NAME, VALUE_503_ERR_CODE, CFGF_NONE),
        CFG_STR(PARAM_REASON_NAME, VALUE_SESSION_LIMIT_ERR, CFGF_NONE),
        CFG_END()
    };

    static cfg_opt_t cps_limit[] {
        CFG_INT(PARAM_LIMIT_NAME, 0, CFGF_NONE),
        CFG_INT(PARAM_CODE_NAME, VALUE_503_ERR_CODE, CFGF_NONE),
        CFG_STR(PARAM_REASON_NAME, VALUE_CPSLIMIT_ERR, CFGF_NONE),
        CFG_END()
    };

    static cfg_opt_t sdm[] {
        CFG_BOOL(PARAM_ALLOW_UAC_NAME, cfg_false, CFGF_NONE),
        CFG_INT(PARAM_CODE_NAME, VALUE_503_ERR_CODE, CFGF_NONE),
        CFG_STR(PARAM_REASON_NAME, VALUE_SDM_ERR_REASON, CFGF_NONE),
        CFG_END()
    };

    static cfg_opt_t ice_cand_filter[] {
        CFG_FUNC(FUNCTION_ALLOW_NAME, &ice_candidate_allow),
        CFG_FUNC(FUNCTION_DENY_NAME, &ice_candidate_deny),
        CFG_END()
    };

    static cfg_opt_t general[] =
    {
        CFG_FUNC("include", &cfg_include),
        CFG_SEC(SECTION_ICE_CAND_FILTER_NAME, ice_cand_filter, CFGF_NONE),
        CFG_SEC(SECTION_SESSION_LIMIT_NAME, slimit, CFGF_NONE),
        CFG_SEC(SECTION_OSLIM_NAME, options_slimit, CFGF_NONE),
        CFG_SEC(SECTION_CPS_LIMIT_NAME, cps_limit, CFGF_NONE),
        CFG_SEC(SECCTION_SDM_NAME, sdm, CFGF_NONE),
        CFG_BOOL(PARAM_LOG_PARS_NAME, cfg_true, CFGF_NONE),
        CFG_BOOL(PARAM_STDERR_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_OUTBOUND_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_OUTBOUND_IF_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_CANCEL_ROUTE_SET, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_SYMM_RTP_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_FORCE_SYMM_PAIR_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_USE_RAW_SOCK_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_DISABLE_DNS_SRV_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_DETECT_INBAND_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_SIP_NAT_HANDLING_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_NEXT_HOP_1ST_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_PROXY_STICKY_AUTH_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_NOTIFY_LOWER_CSEQ_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_ENABLE_RTSP_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_ENABLE_SRTP_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_ENABLE_ICE_NAME, cfg_true, CFGF_NONE),
        CFG_BOOL(PARAM_LOG_SESSIONS_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_LOG_EVENTS_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_SINGLE_CODEC_INOK_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_ACCEPT_FORKED_DLG_NAME, cfg_false, CFGF_NONE),
        CFG_BOOL(PARAM_DTMF_OFFER_MRATE_NAME, cfg_false, CFGF_NONE),
        CFG_INT(PARAM_DTMF_DEFAULT_VOLUME, 20, CFGF_NONE),
        CFG_INT(PARAM_BL_TTL_NAME, VALUE_BL_TTL, CFGF_NONE),
        CFG_INT(PARAM_UDP_RECVBUF_NAME, VALUE_UDP_RECVBUF, CFGF_NONE),
        CFG_INT(PARAM_SESS_PROC_THREADS_NAME, VALUE_NUM_SESSION_PROCESSORS, CFGF_NODEFAULT),
        CFG_INT(PARAM_MEDIA_THREADS_NAME, VALUE_NUM_MEDIA_PROCESSORS, CFGF_NONE),
        CFG_INT(PARAM_SIP_TCP_SERVERS_NAME, VALUE_NUM_SIP_SERVERS, CFGF_NONE),
        CFG_INT(PARAM_SIP_UDP_SERVERS_NAME, VALUE_NUM_SIP_SERVERS, CFGF_NONE),
        CFG_INT(PARAM_RTP_RECEIVERS_NAME, VALUE_NUM_RTP_RECEIVERS, CFGF_NONE),
        CFG_INT(PARAM_NODE_ID_NAME, 0, CFGF_NONE),
        CFG_INT(PARAM_MAX_FORWARDS_NAME, 70, CFGF_NONE),
        CFG_INT(PARAM_MAX_SHUTDOWN_TIME_NAME, VALUE_MAX_SHUTDOWN_TIME, CFGF_NONE),
        CFG_INT(PARAM_DEAD_RTP_TIME_NAME, VALUE_DEAD_RTP_TIME, CFGF_NONE),
        CFG_INT(PARAM_SYMMETRIC_DELAY_NAME, VALUE_SYMMETRIC_RTP_DELAY, CFGF_NONE),
        CFG_INT(PARAM_SYMMETRIC_PACKETS_NAME, 0, CFGF_NONE),
        CFG_STR(PARAM_SYMMETRIC_MODE_NAME, VALUE_PACKETS, CFGF_NONE),
        CFG_STR(PARAM_RSR_PATH_NAME, VALUE_RSR_PATH, CFGF_NONE),
        CFG_STR(PARAM_DUMP_PATH_NAME, VALUE_LOG_DUMP_PATH, CFGF_NONE),
        CFG_STR(PARAM_LOG_RAW_NAME, VALUE_LOG_DEBUG, CFGF_NONE),
        CFG_STR(PARAM_LOG_LEVEL_NAME, VALUE_LOG_INFO, CFGF_NONE),
        CFG_STR(PARAM_LOG_STDERR_LEVEL_NAME, VALUE_LOG_INFO, CFGF_NONE),
        CFG_STR(PARAM_SL_FACILITY_NAME, "", CFGF_NODEFAULT),
        CFG_STR(PARAM_OUTBOUND_PROXY_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_NEXT_HOP_NAME, "", CFGF_NODEFAULT),
        CFG_STR(PARAM_OPT_TRANSCODE_OUT_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_OPT_TRANSCODE_IN_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_TRANSCODE_OUT_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_TRANSCODE_IN_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_SIGNATURE_NAME, nullptr, CFGF_NONE),
        CFG_STR(PARAM_SDP_ORIGIN_NAME, DEFAULT_SDP_ORIGIN, CFGF_NONE),
        CFG_STR(PARAM_SDP_SESSION_NAME, DEFAULT_SDP_SESSION_NAME, CFGF_NONE),
        CFG_STR(PARAM_DTMF_DETECTOR_NAME, VALUE_SPANDSP, CFGF_NONE),
        CFG_STR(PARAM_100REL_NAME, VALUE_SUPPORTED, CFGF_NONE),
        CFG_STR(PARAM_UNHDL_REP_LOG_LVL_NAME, VALUE_LOG_ERR, CFGF_NONE),
        CFG_STR(PARAM_PCAP_UPLOAD_QUEUE_NAME, "", CFGF_NONE),
        CFG_STR_LIST(PARAM_CODEC_ORDER_NAME, 0, CFGF_NODEFAULT),
        CFG_STR_LIST(PARAM_EXCLUDE_PAYLOADS_NAME, 0, CFGF_NODEFAULT),
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
        CFG_BOOL(PARAM_ENABLE_ZRTP_NAME, cfg_true, CFGF_NONE),
        CFG_STR(PARAM_TLS_SSL_KEY_LOG_FILE, "", CFGF_NONE),
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
#ifndef DISABLE_DAEMON_MODE
        CFG_BOOL(PARAM_DEAMON_NAME, cfg_true, CFGF_NONE),
        CFG_STR(PARAM_DEAMON_UID_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_DEAMON_GID_NAME, "", CFGF_NONE),
#endif /* !DISABLE_DAEMON_MODE */
        CFG_END()
    };
/**********************************************************************************************/
/*                                        routing section                                     */
/**********************************************************************************************/
    static cfg_opt_t routing[] =
    {
        CFG_FUNC("include", &cfg_include),
        CFG_STR(PARAM_APP_REG_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_APP_OPT_NAME, "", CFGF_NONE),
        CFG_STR(PARAM_APP_NAME, "", CFGF_NONE),
        CFG_END()
    };

/**********************************************************************************************/
/*                                         global section                                     */
/**********************************************************************************************/
    static cfg_opt_t opt[] =
    {
        CFG_FUNC("include", &cfg_include),
        CFG_SEC(SECTION_SIGIF_NAME, interfaces, CFGF_NODEFAULT),
        CFG_SEC(SECTION_MEDIAIF_NAME, media_interfaces, CFGF_NODEFAULT),
        CFG_SEC(SECTION_MODULES_NAME, modules, CFGF_NODEFAULT),
        CFG_SEC(SECTION_GENERAL_NAME, general, CFGF_NODEFAULT),
        CFG_SEC(SECTION_ROUTING_NAME, routing, CFGF_NODEFAULT),
        CFG_END()
    };
};

#pragma GCC diagnostic pop

/*******************************************************************************************************/
/*                                                                                                     */
/*                                       config functions                                              */
/*                                                                                                     */
/*******************************************************************************************************/
static int ice_candidate_allow(cfg_t *cfg, cfg_opt_t *opt, int argc, const char **argv)
{
    AmConfig.ice_candidate_acl.emplace_back();
    IPTree& acl = AmConfig.ice_candidate_acl.back();
    for(int i = 0; i < argc; i++) {
        AmSubnet net;
        if(!net.parse(argv[i])) {
            ERROR("incorrect subnet addr %s in ice candidate allow filter", argv[i]);
            return -1;
        }
        acl.addSubnet(net, true);
    }
    return 0;
}

static int ice_candidate_deny(cfg_t *cfg, cfg_opt_t *opt, int argc, const char **argv)
{
    AmConfig.ice_candidate_acl.emplace_back();
    IPTree& acl = AmConfig.ice_candidate_acl.back();
    for(int i = 0; i < argc; i++) {
        AmSubnet net;
        if(!net.parse(argv[i])) {
            ERROR("incorrect subnet addr %s in ice candidate deny filter", argv[i]);
            return -1;
        }
        acl.addSubnet(net, false);
    }
    return 0;
}

/*******************************************************************************************************/
/*                                                                                                     */
/*                                       error functions                                               */
/*                                                                                                     */
/*******************************************************************************************************/
static void cfg_error_callback(cfg_t *cfg, const char *fmt, va_list ap)
{
    char buf[2048];
    char *s = buf;
    char *e = s+sizeof(buf);

    if(cfg->title) {
        s += snprintf(s,static_cast<size_t>(e-s), "%s:%d [%s/%s]: ",
            cfg->filename,cfg->line,cfg->name,cfg->title);
    } else {
        s += snprintf(s,static_cast<size_t>(e-s), "%s:%d [%s]: ",
            cfg->filename,cfg->line,cfg->name);
    }
    s += vsnprintf(s,static_cast<size_t>(e-s),fmt,ap);

    ERROR("%.*s",cint(s-buf),buf);
}

/*******************************************************************************************************/
/*                                                                                                     */
/*                                       Validation functions                                          */
/*                                                                                                     */
/*******************************************************************************************************/
std::optional<int> parse_log_level(const std::string& level)
{
    int n;
    if (sscanf(level.c_str(), "%i", &n) == 1) {
        if (n < L_ERR || n > L_DBG_3) {
            return std::nullopt;
        }
        return n;
    }

    std::string s(level);
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);

    if (s == VALUE_LOG_NO) {
        n = -1;
    } else if (s == VALUE_LOG_ERR) {
        n = L_ERR;
    } else if (s == VALUE_LOG_WARN) {
        n = L_WARN;
    } else if (s == VALUE_LOG_INFO) {
        n = L_INFO;
    } else if (s==VALUE_LOG_DEBUG) {
        n = L_DBG;
    } else if (s==VALUE_LOG_DEBUG2) {
        n = L_DBG_2;
    } else if (s==VALUE_LOG_DEBUG3) {
        n = L_DBG_3;
    } else {
        fprintf(stderr,"unknown loglevel value: %s",level.c_str());
        return std::nullopt;
    }
    return n;
}

int validate_log_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    auto ret = parse_log_level(value);
    if(!ret) {
        ERROR("invalid value \'%s\' of the option \'%s\' - \
              must be \'no\',\'error\',\'info\',\'warn\',\'debug\' or number from %d to %d",
              value.c_str(), opt->name, L_ERR, L_DBG);
    }
    return ret ? 0 : 1;
}

int validate_method_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    bool valid = (value == VALUE_DROP || value == VALUE_REJECT);
    if(!valid) {
        ERROR("invalid value \'%s\' of the option \'%s\' - must be \'drop\' or \'reject\'", value.c_str(), opt->name);
    }
    return valid ? 0 : 1;
}

int validate_ip6(const std::string& address)
{
    sockaddr_storage addr;
    if(!am_inet_pton(address.c_str(), &addr)){
        ERROR("invalid value \'%s\' for the addressL: not an address", address.c_str());
        return 1;
    }

    bool valid = addr.ss_family == AF_INET6;
    if(!valid) {
        ERROR("invalid value \'%s\' for the address: not IPv6 address", address.c_str());
    }
    return valid ? 0 : 1;
}

int validate_ip6_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    return validate_ip6(value);
}

int validate_ip4(const std::string& address)
{
    sockaddr_storage addr;
    if(!am_inet_pton(address.c_str(), &addr)){
        ERROR("invalid value \'%s\' of address", address.c_str());
        return 1;
    }

    bool valid = addr.ss_family == AF_INET;
    if(!valid) {
        ERROR("invalid value \'%s\' for the address: not IPv4 address", address.c_str());
    }
    return valid ? 0 : 1;
}

int validate_ip4_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    return validate_ip4(value);
}

int validate_dtmf_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    bool valid = (value == VALUE_SPANDSP || value == VALUE_INTERNAL);
    if(!valid) {
        ERROR("invalid value \'%s\' of the option \'%s\' - must be \'spandsp\' or \'internal\'", value.c_str(), opt->name);
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
        ERROR("invalid value \'%s\' of the option \'%s\' - must be \'disabled\', \'supported\', \'require\' or \'off\'", value.c_str(), opt->name);
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
        ERROR("invalid value \'%s\' of the option \'%s\' - must be \'libsamplerate\', \'internal\' or \'unavailable\'", value.c_str(), opt->name);
    }
    return valid ? 0 : 1;
}

int validate_symmetric_mode_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    bool valid = (value == VALUE_PACKETS ||
                  value == VALUE_DELAY);
    if(!valid) {
        ERROR("invalid value \'%s\' of the option \'%s\' - must be \'packets\' or \'delay\'", value.c_str(), opt->name);
    }
    return valid ? 0 : 1;
}

int validate_tls_protocol_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    bool valid = tls_settings::protocolFromStr(value) != tls_settings::UNSUPPORT;
    if(!valid) {
        ERROR("invalid value \'%s\' of the option \'%s\' - must be \'TLSv1.2\' or \'TLSv1.3\'", value.c_str(), opt->name);
    }
    return valid ? 0 : 1;
}

int validate_dtls_protocol_func(cfg_t *cfg, cfg_opt_t *opt)
{
    std::string value = cfg_getstr(cfg, opt->name);
    bool valid = dtls_settings::protocolFromStr(value) != dtls_settings::UNSUPPORT;
    if(!valid) {
        ERROR("invalid value \'%s\' of the option \'%s\' - must be \'DTLSv1.2\'", value.c_str(), opt->name);
    }
    return valid ? 0 : 1;
}

static int check_dir_write_permissions(const string &dir, const char *opt_name)
{
    std::ofstream st;
    string testfile = dir + "/test";
    st.open(testfile.c_str(),std::ofstream::out | std::ofstream::trunc);
    if(!st.is_open()){
        ERROR("failed to write test file in %s directory: %s",
              opt_name, dir.c_str());
        return 1;
    }
    st.close();
    std::remove(testfile.c_str());
    return 0;
}
#define ENSURE_CFG_DIR_IS_WRITABLE(var) if(check_dir_write_permissions(config->var,#var)) return -1;


ConfigContainer::ConfigContainer()
: plugin_path(PLUG_IN_PATH)
, log_dump_path()
, session_proc_threads(VALUE_NUM_SESSION_PROCESSORS)
, ignore_sig_chld(true)
, ignore_sig_pipe(true)
, shutdown_mode(false)
, dump_level(0)
#ifndef DISABLE_DAEMON_MODE
, deamon_pid_file(DEFAULT_DAEMON_PID_FILE)
#endif
{}

/*******************************************************************************************************/
/*                                                                                                     */
/*                                       AmLcConfig class                                              */
/*                                                                                                     */
/*******************************************************************************************************/
AmLcConfig::AmLcConfig()
: config_path(CONF_FILE_PATH)
, is_default_signature(false)
{}

AmLcConfig::~AmLcConfig()
{
    //INFO("~AmLcConfig");
    if(m_cfg) {
        cfg_free(m_cfg);
    }
}

void AmLcConfig::setValidationFunction(cfg_t* cfg)
{
// interfaces ACL validation
#define set_method_validator(IF_NAME, PROTO_NAME, PROTO_VERSION, METHOD_NAME) \
    cfg_set_validate_func(cfg,\
        IF_NAME "|" SECTION_IF_NAME "|" PROTO_VERSION "|"\
        PROTO_NAME "|" METHOD_NAME "|" PARAM_METHOD_NAME,\
        validate_method_func)

#define set_sip_acl_validator_proto_version(PROTO_NAME, PROTO_VERSION) \
    set_method_validator(SECTION_SIGIF_NAME, PROTO_NAME, PROTO_VERSION, SECTION_OPT_NAME);\
    set_method_validator(SECTION_SIGIF_NAME, PROTO_NAME, PROTO_VERSION, SECTION_ORIGACL_NAME);\
    set_method_validator(SECTION_SIGIF_NAME, PROTO_NAME, PROTO_VERSION, SECTION_REG_ACL_NAME);

#define set_acl_validator_proto(DEF_NAME, PROTO_NAME) \
    DEF_NAME(PROTO_NAME, SECTION_IP4_NAME);\
    DEF_NAME(PROTO_NAME, SECTION_IP6_NAME);

#define set_sip_acl_validator_proto(PROTO_NAME) \
    set_acl_validator_proto(set_sip_acl_validator_proto_version, PROTO_NAME)

    set_sip_acl_validator_proto(SECTION_SIP_UDP_NAME);
    set_sip_acl_validator_proto(SECTION_SIP_TCP_NAME);
    set_sip_acl_validator_proto(SECTION_SIP_TLS_NAME);
    set_sip_acl_validator_proto(SECTION_SIP_WS_NAME);
    set_sip_acl_validator_proto(SECTION_SIP_WSS_NAME);

#undef set_sip_acl_validator_proto
#undef set_acl_validator_proto
#undef set_sip_acl_validator_proto_version
#undef set_method_validator

// ip of interfaces validation
#define set_ip_func_validator(INTERFACE_NAME, PROTO_NAME) \
    cfg_set_validate_func(cfg,\
        INTERFACE_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|"\
        PROTO_NAME "|" PARAM_ADDRESS_NAME,\
        validate_ip6_func);\
    cfg_set_validate_func(cfg,\
        INTERFACE_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|"\
        PROTO_NAME "|" PARAM_ADDRESS_NAME,\
        validate_ip4_func);

    set_ip_func_validator(SECTION_SIGIF_NAME, SECTION_SIP_UDP_NAME);
    set_ip_func_validator(SECTION_SIGIF_NAME, SECTION_SIP_TCP_NAME);
    set_ip_func_validator(SECTION_SIGIF_NAME, SECTION_SIP_TLS_NAME);
    set_ip_func_validator(SECTION_SIGIF_NAME, SECTION_SIP_WS_NAME);
    set_ip_func_validator(SECTION_SIGIF_NAME, SECTION_SIP_WSS_NAME);
    set_ip_func_validator(SECTION_MEDIAIF_NAME, SECTION_RTP_NAME);
    set_ip_func_validator(SECTION_MEDIAIF_NAME, SECTION_RTSP_NAME);

#undef set_ip_func_validator

#define set_tls_version_func_validator(INTERFACE_NAME, PROTO_NAME) \
    cfg_set_validate_func(cfg,\
        INTERFACE_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|"\
        PROTO_NAME "|" SECTION_CLIENT_NAME "|" PARAM_PROTOCOLS_NAME,\
        validate_tls_protocol_func);\
    cfg_set_validate_func(cfg,\
        INTERFACE_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|"\
        PROTO_NAME "|" SECTION_SERVER_NAME "|" PARAM_PROTOCOLS_NAME,\
        validate_tls_protocol_func);\
    cfg_set_validate_func(cfg,\
        INTERFACE_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|"\
        PROTO_NAME "|" SECTION_CLIENT_NAME "|" PARAM_PROTOCOLS_NAME,\
        validate_tls_protocol_func);\
    cfg_set_validate_func(cfg,\
        INTERFACE_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|"\
        PROTO_NAME "|" SECTION_SERVER_NAME "|" PARAM_PROTOCOLS_NAME,\
        validate_tls_protocol_func);\

    set_tls_version_func_validator(SECTION_SIGIF_NAME, SECTION_SIP_TLS_NAME);
    set_tls_version_func_validator(SECTION_SIGIF_NAME, SECTION_SIP_WSS_NAME);
    cfg_set_validate_func(cfg,
        SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP6_NAME "|"\
        SECTION_RTP_NAME "|" SECTION_SRTP_NAME "|" SECTION_DTLS_NAME "|"
        SECTION_SERVER_NAME "|" PARAM_PROTOCOLS_NAME,\
        validate_dtls_protocol_func);
    cfg_set_validate_func(cfg,
        SECTION_MEDIAIF_NAME "|" SECTION_IF_NAME "|" SECTION_IP4_NAME "|"\
        SECTION_RTP_NAME "|" SECTION_SRTP_NAME "|" SECTION_DTLS_NAME "|"
        SECTION_SERVER_NAME "|" PARAM_PROTOCOLS_NAME,\
        validate_dtls_protocol_func);

#undef set_tls_version_func_validator

// general validation
    cfg_set_validate_func(cfg, SECTION_GENERAL_NAME "|" PARAM_LOG_RAW_NAME , validate_log_func);
    cfg_set_validate_func(cfg, SECTION_GENERAL_NAME "|" PARAM_LOG_LEVEL_NAME , validate_log_func);
    cfg_set_validate_func(cfg, SECTION_GENERAL_NAME "|" PARAM_LOG_STDERR_LEVEL_NAME , validate_log_func);
    cfg_set_validate_func(cfg, SECTION_GENERAL_NAME "|" PARAM_DTMF_DETECTOR_NAME , validate_dtmf_func);
    cfg_set_validate_func(cfg, SECTION_GENERAL_NAME "|" PARAM_100REL_NAME , validate_100rel_func);
    cfg_set_validate_func(cfg, SECTION_GENERAL_NAME "|" PARAM_UNHDL_REP_LOG_LVL_NAME , validate_log_func);
    cfg_set_validate_func(cfg, SECTION_GENERAL_NAME "|" PARAM_RESAMPLE_LIBRARY_NAME , validate_resampling_func);
    cfg_set_validate_func(cfg, SECTION_GENERAL_NAME "|" PARAM_SYMMETRIC_MODE_NAME , validate_symmetric_mode_func);

    cfg_set_error_function(cfg,cfg_error_callback);
}



int AmLcConfig::readConfiguration(ConfigContainer* config)
{
    if(m_cfg)
        cfg_free(m_cfg);
    m_cfg = cfg_init(Config::opt, 0);
    if(!m_cfg) return -1;
    setValidationFunction(m_cfg);

    config->sip_ifs.clear();

    switch(cfg_parse(m_cfg, config_path.c_str())) {
    case CFG_SUCCESS:
        break;
    case CFG_FILE_ERROR:
        ERROR("failed to open configuration file: %s (%s)",
            config_path.c_str(), strerror(errno));
        return -1;
    case CFG_PARSE_ERROR:
        ERROR("failed to parse configuration file: %s", config_path.c_str());
        return -1;
    default:
        ERROR("got unexpected error on configuration file processing: %s", config_path.c_str());
        return -1;
    }

    if(readGeneral(m_cfg, config) ||
       readSigInterfaces(m_cfg, config) ||
       readMediaInterfaces(m_cfg, config) ||
       readModules(m_cfg, config) ||
       readRoutings(m_cfg, config) ||
       checkSipInterfaces(config)) {
        return -1;
    }

    if(m_cfg)
        cfg_free(m_cfg);
    m_cfg = nullptr;
    return 0;
}

int AmLcConfig::readGeneral(cfg_t* cfg, ConfigContainer* config)
{
    if(!cfg_size(cfg, SECTION_GENERAL_NAME)) {
        ERROR(SECTION_GENERAL_NAME " absent");
        return -1;
    }
    cfg_t* gen = cfg_getsec(cfg, SECTION_GENERAL_NAME);

    config->log_dump_path = cfg_getstr(gen, PARAM_DUMP_PATH_NAME);
    ENSURE_CFG_DIR_IS_WRITABLE(log_dump_path);

    config->rsr_path = cfg_getstr(gen, PARAM_RSR_PATH_NAME);
    ENSURE_CFG_DIR_IS_WRITABLE(rsr_path);

    if(config == &m_config) {
        _SipCtrlInterface::log_parsed_messages = cfg_getbool(gen, PARAM_LOG_PARS_NAME);
        _trans_layer::default_bl_ttl = cuint(cfg_getint(gen, PARAM_BL_TTL_NAME));
        trsp_socket::log_level_raw_msgs =
            parse_log_level(cfg_getstr(gen, PARAM_LOG_RAW_NAME)).value_or(L_DBG);
        _SipCtrlInterface::log_parsed_messages = cfg_getbool(gen, PARAM_LOG_PARS_NAME);
        _SipCtrlInterface::udp_rcvbuf = static_cast<int>(cfg_getint(gen, PARAM_UDP_RECVBUF_NAME));
        sip_timer_t2 = cuint(cfg_getint(gen, PARAM_SIP_TIMER_T2_NAME));
        for (int t = STIMER_A; t < __STIMER_MAX; t++) {
            std::string timer_cfg = std::string("sip_timer_") +
                static_cast<char>(tolower(*timer_name(cuint(t))));
            sip_timers[t] = cuint(cfg_getint(gen, timer_cfg.c_str()));
            DBG3("Set SIP Timer '%s' to %u ms", timer_name(cuint(t)), sip_timers[t]);
        }

        setLogLevel(cfg_getstr(gen, PARAM_LOG_LEVEL_NAME));
        setLogStderr(cfg_getbool(gen, PARAM_STDERR_NAME));
        setStderrLogLevel(cfg_getstr(gen, PARAM_LOG_STDERR_LEVEL_NAME));
#ifndef DISABLE_SYSLOG_LOG
        if (cfg_size(gen, PARAM_SL_FACILITY_NAME)) {
            set_syslog_facility(cfg_getstr(gen, PARAM_SL_FACILITY_NAME), SEMS_APP_NAME);
        }
#endif
        _resolver::disable_srv = cfg_getbool(gen, PARAM_DISABLE_DNS_SRV_NAME);
    }
    if (cfg_size(gen, PARAM_SESS_PROC_THREADS_NAME)) {
#ifdef SESSION_THREADPOOL
        config->session_proc_threads = cint(cfg_getint(gen, PARAM_SESS_PROC_THREADS_NAME));
        if (config->session_proc_threads < 1) {
            ERROR("invalid session_processor_threads value specified."
                  " need at least one thread\n");
            return -1;
        }
#else
        WARN("session_processor_threads specified in sems.conf,");
        WARN("but SEMS is compiled without SESSION_THREADPOOL support.");
        WARN("set USE_THREADPOOL in Makefile.defs to enable session thread pool.");
        WARN("SEMS will start now, but every call will have its own thread.");
#endif
    }

    config->max_forwards = cuint(cfg_getint(gen, PARAM_MAX_FORWARDS_NAME));
    if(config->max_forwards > 70 || config->max_forwards < 1) {
        ERROR("invalid max_forwards value specified."
                  "it must be in range from 1 to 70\n");
            return -1;
    }

    std::string value = cfg_getstr(gen, PARAM_SYMMETRIC_MODE_NAME);
    if(value == VALUE_PACKETS) config->symmetric_rtp_mode = ConfigContainer::SM_RTP_PACKETS;
    else config->symmetric_rtp_mode = ConfigContainer::SM_RTP_DELAY;

    config->force_outbound_proxy = cfg_getbool(gen, PARAM_FORCE_OUTBOUND_NAME);
    config->force_outbound_if = cfg_getbool(gen, PARAM_FORCE_OUTBOUND_IF_NAME);
    config->force_cancel_route_set = cfg_getbool(gen, PARAM_FORCE_CANCEL_ROUTE_SET);
    config->force_symmetric_rtp = cfg_getbool(gen, PARAM_FORCE_SYMM_RTP_NAME);
    config->force_symmetric_candidate = cfg_getbool(gen, PARAM_FORCE_SYMM_PAIR_NAME);
    config->symmetric_rtp_packets = cint(cfg_getint(gen, PARAM_SYMMETRIC_PACKETS_NAME));
    config->symmetric_rtp_delay = cint(cfg_getint(gen, PARAM_SYMMETRIC_DELAY_NAME));
    config->use_raw_sockets = cfg_getbool(gen, PARAM_USE_RAW_SOCK_NAME);
    config->detect_inband_dtmf = cfg_getbool(gen, PARAM_DETECT_INBAND_NAME);
    config->sip_nat_handling = cfg_getbool(gen, PARAM_SIP_NAT_HANDLING_NAME);
    config->proxy_sticky_auth = cfg_getbool(gen, PARAM_PROXY_STICKY_AUTH_NAME);
    config->ignore_notify_lower_cseq = cfg_getbool(gen, PARAM_NOTIFY_LOWER_CSEQ_NAME);
    config->log_events = cfg_getbool(gen, PARAM_LOG_EVENTS_NAME);
    config->single_codec_in_ok = cfg_getbool(gen, PARAM_SINGLE_CODEC_INOK_NAME);
    config->enable_rtsp = cfg_getbool(gen, PARAM_ENABLE_RTSP_NAME);
    config->enable_srtp = cfg_getbool(gen, PARAM_ENABLE_SRTP_NAME);
    config->enable_ice = cfg_getbool(gen, PARAM_ENABLE_ICE_NAME);
    config->log_sessions = cfg_getbool(gen, PARAM_LOG_SESSIONS_NAME);
    config->accept_forked_dialogs = cfg_getbool(gen, PARAM_ACCEPT_FORKED_DLG_NAME);
	if(config->use_raw_sockets && (raw_sender::init() < 0)) {
        config->use_raw_sockets = false;
	}
    if(cfg_size(gen, PARAM_NEXT_HOP_NAME)) {
        config->next_hop = cfg_getstr(gen, PARAM_NEXT_HOP_NAME);
        config->next_hop_1st_req = cfg_getbool(gen, PARAM_NEXT_HOP_1ST_NAME);
    }

    WITH_SECTION(SECTION_SESSION_LIMIT_NAME) {
        config->session_limit =  cuint(cfg_getint(s, PARAM_LIMIT_NAME));
        config->session_limit_err_code = cuint(cfg_getint(s, PARAM_CODE_NAME));
        config->session_limit_err_reason = cfg_getstr(s, PARAM_REASON_NAME);
    }

    WITH_SECTION(SECTION_OSLIM_NAME) {
        config->options_session_limit = cuint(cfg_getint(s, PARAM_LIMIT_NAME));
        config->options_session_limit_err_code = cuint(cfg_getint(s, PARAM_CODE_NAME));
        config->options_session_limit_err_reason = cfg_getstr(s, PARAM_REASON_NAME);
    }

    WITH_SECTION(SECTION_CPS_LIMIT_NAME) {
        AmSessionContainer::instance()->setCPSLimit(cuint(cfg_getint(s, PARAM_LIMIT_NAME)));
        config->cps_limit_err_code = cuint(cfg_getint(s, PARAM_CODE_NAME));
        config->cps_limit_err_reason = cfg_getstr(s, PARAM_REASON_NAME);
    }

    WITH_SECTION(SECCTION_SDM_NAME) {
        config->shutdown_mode_err_code = cuint(cfg_getint(s, PARAM_CODE_NAME));
        config->shutdown_mode_err_reason = cfg_getstr(s, PARAM_REASON_NAME);
        config->shutdown_mode_allow_uac = cfg_getbool(s, PARAM_ALLOW_UAC_NAME);
    }

    config->media_proc_threads = cint(cfg_getint(gen, PARAM_MEDIA_THREADS_NAME));
    config->rtp_recv_threads = cint(cfg_getint(gen, PARAM_RTP_RECEIVERS_NAME));
    config->sip_tcp_server_threads = cint(cfg_getint(gen, PARAM_SIP_TCP_SERVERS_NAME));
    config->sip_udp_server_threads = cint(cfg_getint(gen, PARAM_SIP_UDP_SERVERS_NAME));
    config->outbound_proxy = cfg_getstr(gen, PARAM_OUTBOUND_PROXY_NAME);
    config->options_transcoder_out_stats_hdr = cfg_getstr(gen, PARAM_OPT_TRANSCODE_OUT_NAME);
    config->options_transcoder_in_stats_hdr = cfg_getstr(gen, PARAM_OPT_TRANSCODE_IN_NAME);
    config->transcoder_out_stats_hdr = cfg_getstr(gen, PARAM_TRANSCODE_OUT_NAME);
    config->transcoder_in_stats_hdr = cfg_getstr(gen, PARAM_TRANSCODE_IN_NAME);
    config->sdp_origin = cfg_getstr(gen, PARAM_SDP_ORIGIN_NAME);
    config->sdp_session_name = cfg_getstr(gen, PARAM_SDP_SESSION_NAME);
    config->node_id = cint(cfg_getint(gen, PARAM_NODE_ID_NAME));
    if(config->node_id!=0) config->node_id_prefix = int2str(config->node_id) + "-";
    config->max_shutdown_time = cuint(cfg_getint(gen, PARAM_MAX_SHUTDOWN_TIME_NAME));
    config->dead_rtp_time = cuint(cfg_getint(gen, PARAM_DEAD_RTP_TIME_NAME));
    value = cfg_getstr(gen, PARAM_DTMF_DETECTOR_NAME);
    if(value == VALUE_SPANDSP) config->default_dtmf_detector = Dtmf::SpanDSP;
    else config->default_dtmf_detector = Dtmf::SEMSInternal;
    config->dtmf_offer_multirate = cfg_getbool(gen, PARAM_DTMF_OFFER_MRATE_NAME);
    config->dtmf_default_volume = cfg_getint(gen, PARAM_DTMF_DEFAULT_VOLUME);
    for(unsigned int i = 0; i < cfg_size(gen, PARAM_CODEC_ORDER_NAME); i++) {
        config->codec_order.push_back(cfg_getnstr(gen, PARAM_CODEC_ORDER_NAME, i));
    }
    for(unsigned int i = 0; i < cfg_size(gen, PARAM_EXCLUDE_PAYLOADS_NAME); i++) {
        config->exclude_payloads.push_back(cfg_getnstr(gen, PARAM_EXCLUDE_PAYLOADS_NAME, i));
    }

    value = cfg_getstr(gen, PARAM_100REL_NAME);
    if(value == VALUE_DISABLE || value == VALUE_OFF) config->rel100 = Am100rel::REL100_DISABLED;
    else if(value == VALUE_SUPPORTED) config->rel100 = Am100rel::REL100_SUPPORTED;
    else if(value == VALUE_REQUIRE) config->rel100 = Am100rel::REL100_REQUIRE;
    config->unhandled_reply_log_level =
        static_cast<Log_Level>(
            parse_log_level(cfg_getstr(gen, PARAM_UNHDL_REP_LOG_LVL_NAME)).value_or(L_ERR));
    config->pcap_upload_queue_name = cfg_getstr(gen, PARAM_PCAP_UPLOAD_QUEUE_NAME);
    value = cfg_getstr(gen, PARAM_RESAMPLE_LIBRARY_NAME);
    if(value == VALUE_LIBSAMPLERATE) config->resampling_implementation_type = AmAudio::LIBSAMPLERATE;
    else if(value == VALUE_UNAVAILABLE) config->resampling_implementation_type = AmAudio::UNAVAILABLE;
    else if(value == VALUE_INTERNAL) config->resampling_implementation_type = AmAudio::INTERNAL_RESAMPLER;
    config->enable_zrtp = cfg_getbool(gen, PARAM_ENABLE_ZRTP_NAME);
    config->ssl_key_log_filepath = cfg_getstr(gen, PARAM_TLS_SSL_KEY_LOG_FILE);
#ifndef DISABLE_DAEMON_MODE
    config->deamon_mode = cfg_getbool(gen, PARAM_DEAMON_NAME);
    config->deamon_uid = cfg_getstr(gen, PARAM_DEAMON_UID_NAME);
    config->deamon_gid = cfg_getstr(gen, PARAM_DEAMON_GID_NAME);
#endif /* !DISABLE_DAEMON_MODE */

    applySignature(cfg_getstr(gen, PARAM_SIGNATURE_NAME));

    return 0;
}

int AmLcConfig::readRoutings(cfg_t* cfg, ConfigContainer* config)
{
    if(!cfg_size(cfg, SECTION_ROUTING_NAME)) {
        ERROR(SECTION_ROUTING_NAME " absent");
        return -1;
    }
    cfg_t* routing = cfg_getsec(cfg, SECTION_ROUTING_NAME);

    config->register_application = cfg_getstr(routing, PARAM_APP_REG_NAME);
    config->options_application = cfg_getstr(routing, PARAM_APP_OPT_NAME);

    string apps_str = cfg_getstr(routing, PARAM_APP_NAME);
    auto apps = explode(apps_str,"|");
    config->applications.resize(apps.size());
    int app_selector_id = 0;
    for(const auto &app_str: apps) {
        ConfigContainer::app_selector &app = config->applications[static_cast<size_t>(app_selector_id)];
        app.application = app_str;
        if (app_str == "$(ruri.user)") {
            app.app_select = ConfigContainer::App_RURIUSER;
        } else if (app_str == "$(ruri.param)") {
            app.app_select = ConfigContainer::App_RURIPARAM;
        } else if (app_str == "$(apphdr)") {
            app.app_select = ConfigContainer::App_APPHDR;
        } else if (app_str == "$(mapping)") {
            app.app_select = ConfigContainer::App_MAPPING;
            string appcfg_fname = AmConfig.configs_path + "app_mapping.conf";
            DBG("Loading application mapping...");
            if (!read_regex_mapping(appcfg_fname, "=>", "application mapping",
                app.app_mapping))
            {
                ERROR("reading application mapping");
                return -1;
            }
        } else {
            app.app_select = ConfigContainer::App_SPECIFIED;
        }
        app_selector_id++;
    }
    return 0;
}

int AmLcConfig::readModules(cfg_t* cfg, ConfigContainer* config)
{
    if(!cfg_size(cfg, SECTION_MODULES_NAME)) {
        ERROR(SECTION_MODULES_NAME " absent");
        return -1;
    }
    cfg_t* modules_ = cfg_getsec(cfg, SECTION_MODULES_NAME);

    unsigned int mCount;
    config->modules_path = cfg_getstr(modules_, PARAM_PATH_NAME);
    config->configs_path = cfg_getstr(modules_, PARAM_CPATH_NAME);
    mCount = cfg_size(modules_, SECTION_MODULE_NAME);
    for(unsigned int i = 0; i < mCount; i++) {
        cfg_t* module = cfg_getnsec(modules_, SECTION_MODULE_NAME, i);
        std::string name = module->title;
        if(name == "rtsp_client") {
            if(RtspClient::instance()->configure(module->raw_info->raw)){
                ERROR("error in cofiguration of rtsp client");
                return -1;
            }
        } else {
            config->modules.push_back(name);
            config->module_config.insert(std::make_pair(name, module->raw_info->raw));
        }

        freeRawValues(module);
    }
    mCount = cfg_size(modules_, SECTION_MODULE_GLOBAL_NAME);
    for(unsigned int i = 0; i < mCount; i++) {
        cfg_t* module = cfg_getnsec(modules_, SECTION_MODULE_GLOBAL_NAME, i);
        std::string name = module->title;
        /*printf("raw section value for module '%s':\n---%.*s\n---\n",
              module->title, (int)module->raw_info->raw_len, module->raw_info->raw);*/
        config->modules.push_back(name);
        config->module_config.insert(std::make_pair(name, module->raw_info->raw));
        config->rtld_global_plugins.insert(name + ".so");
        freeRawValues(module);
    }

    return 0;
}

int AmLcConfig::readSigInterfaces(cfg_t* cfg, ConfigContainer* config)
{
    if(!cfg_size(cfg, SECTION_SIGIF_NAME)) {
        ERROR(SECTION_SIGIF_NAME " absent");
        return -1;
    }
    cfg_t* sigif = cfg_getsec(cfg, SECTION_SIGIF_NAME);

    unsigned int ifCount = cfg_size(sigif, SECTION_IF_NAME);
    for(unsigned int i = 0; i < ifCount; i++) {
        config->sip_ifs.emplace_back();
        SIP_interface &sip_if = config->sip_ifs.back();
        cfg_t* if_ = cfg_getnsec(sigif, SECTION_IF_NAME, i);
        sip_if.name = if_->title;
        sip_if.default_media_if = cfg_getstr(if_, PARAM_DEFAULT_MEDIAIF_NAME);

        if(cfg_size(if_, SECTION_IP4_NAME)) {
            cfg_t* ip4 = cfg_getsec(if_, SECTION_IP4_NAME);
            if(cfg_size(ip4, SECTION_SIP_UDP_NAME)) {
                cfg_t* cfg = cfg_getsec(ip4, SECTION_SIP_UDP_NAME);
                SIP_info* info = dynamic_cast<SIP_info*>(readInterface(cfg, sip_if.name, AT_V4));
                if(!info) {
                    return -1;
                }
                sip_if.proto_info.push_back(info);
            }
            if(cfg_size(ip4, SECTION_SIP_TCP_NAME)) {
                cfg_t* cfg = cfg_getsec(ip4, SECTION_SIP_TCP_NAME);
                SIP_info* info = dynamic_cast<SIP_info*>(readInterface(cfg, sip_if.name, AT_V4));
                if(!info) {
                    return -1;
                }
                sip_if.proto_info.push_back(info);
            }
            if(cfg_size(ip4, SECTION_SIP_TLS_NAME)) {
                cfg_t* cfg = cfg_getsec(ip4, SECTION_SIP_TLS_NAME);
                SIP_info* info = dynamic_cast<SIP_info*>(readInterface(cfg, sip_if.name, AT_V4));
                if(!info) {
                    return -1;
                }
                sip_if.proto_info.push_back(info);
            }
            if(cfg_size(ip4, SECTION_SIP_WS_NAME)) {
                cfg_t* cfg = cfg_getsec(ip4, SECTION_SIP_WS_NAME);
                SIP_info* info = dynamic_cast<SIP_info*>(readInterface(cfg, sip_if.name, AT_V4));
                if(!info) {
                    return -1;
                }
                sip_if.proto_info.push_back(info);
            }
            if(cfg_size(ip4, SECTION_SIP_WSS_NAME)) {
                cfg_t* cfg = cfg_getsec(ip4, SECTION_SIP_WSS_NAME);
                SIP_info* info = dynamic_cast<SIP_info*>(readInterface(cfg, sip_if.name, AT_V4));
                if(!info) {
                    return -1;
                }
                sip_if.proto_info.push_back(info);
            }
        }

        if(cfg_size(if_, SECTION_IP6_NAME)) {
            cfg_t* ip6 = cfg_getsec(if_, SECTION_IP6_NAME);
            if(cfg_size(ip6, SECTION_SIP_UDP_NAME)) {
                cfg_t* cfg = cfg_getsec(ip6, SECTION_SIP_UDP_NAME);
                SIP_info* info = dynamic_cast<SIP_info*>(readInterface(cfg, sip_if.name, AT_V6));
                if(!info) {
                    return -1;
                }
                sip_if.proto_info.push_back(info);
            }
            if(cfg_size(ip6, SECTION_SIP_TCP_NAME)) {
                cfg_t* cfg = cfg_getsec(ip6, SECTION_SIP_TCP_NAME);
                SIP_info* info = dynamic_cast<SIP_info*>(readInterface(cfg, sip_if.name, AT_V6));
                if(!info) {
                    return -1;
                }
                sip_if.proto_info.push_back(info);
            }
            if(cfg_size(ip6, SECTION_SIP_TLS_NAME)) {
                cfg_t* cfg = cfg_getsec(ip6, SECTION_SIP_TLS_NAME);
                SIP_info* info = dynamic_cast<SIP_info*>(readInterface(cfg, sip_if.name, AT_V6));
                if(!info) {
                    return -1;
                }
                sip_if.proto_info.push_back(info);
            }
            if(cfg_size(ip6, SECTION_SIP_WS_NAME)) {
                cfg_t* cfg = cfg_getsec(ip6, SECTION_SIP_WS_NAME);
                SIP_info* info = dynamic_cast<SIP_info*>(readInterface(cfg, sip_if.name, AT_V6));
                if(!info) {
                    return -1;
                }
                sip_if.proto_info.push_back(info);
            }
            if(cfg_size(ip6, SECTION_SIP_WSS_NAME)) {
                cfg_t* cfg = cfg_getsec(ip6, SECTION_SIP_WSS_NAME);
                SIP_info* info = dynamic_cast<SIP_info*>(readInterface(cfg, sip_if.name, AT_V6));
                if(!info) {
                    return -1;
                }
                sip_if.proto_info.push_back(info);
            }
        }

        if(sip_if.proto_info.empty()) {
            config->sip_ifs.pop_back();
        } else {
            for(const auto &p: sip_if.proto_info) {
                if(!p->public_domain.empty()) {
                    dns_handle dh;
                    dns_priority priority =  p->type_ip == AT_V4 ? IPv4_only : IPv6_only;
                    sockaddr_storage a;
                    if (resolver::instance()->resolve_name(p->public_domain.data(),
                        &dh,&a, priority) < 0)
                    {
                        WARN("failed to resolve domain: '%s' with priority %s "
                             "(sip interface '%s', transport: %s, protocol: %s)",
                             p->public_domain.data(),
                             dns_priority_str(priority),
                             sip_if.name.data(),
                             p->transportToStr().data(),
                             p->ipTypeToStr().data());
                    }
                }
            }
        }
    }
    return 0;
}

int AmLcConfig::readMediaInterfaces(cfg_t* cfg, ConfigContainer* config)
{
    if(!cfg_size(cfg, SECTION_MEDIAIF_NAME)) {
        ERROR(SECTION_MEDIAIF_NAME " absent");
        return -1;
    }
    cfg_t* mediaif = cfg_getsec(cfg, SECTION_MEDIAIF_NAME);
    unsigned int ifCount = cfg_size(mediaif, SECTION_IF_NAME);
    for(unsigned int i = 0; i < ifCount; i++) {
        config->media_ifs.emplace_back();
        MEDIA_interface &media_if = config->media_ifs.back();
        cfg_t* if_ = cfg_getnsec(mediaif, SECTION_IF_NAME, i);
        media_if.name = if_->title;
        if(cfg_size(if_, SECTION_SRTP_NAME)) {
            //RTP->SRTP specific opts
            if(cfg_size(if_, SECTION_SRTP_NAME)) {
                cfg_t* srtp = cfg_getsec(if_, SECTION_SRTP_NAME);
                if(getMandatoryParameter(srtp, PARAM_ENABLE_SRTP_NAME, media_if.srtp->srtp_enable)) {
                    return -1;
                }
                cfg_t* sdes = cfg_getsec(srtp, SECTION_SDES_NAME);
                for(unsigned int i = 0; i < cfg_size(sdes, PARAM_PROFILES_NAME); i++) {
                    char* profile_name = cfg_getnstr(sdes, PARAM_PROFILES_NAME, i);
                    CryptoProfile profile = SdpCrypto::str2profile(profile_name);
                    if(profile == CP_NONE) {
                        ERROR("incorrect or not supported profile name %s", profile_name);
                        return -1;
                    }
                    media_if.srtp->profiles.push_back(profile);
                }

                cfg_t* zrtp = cfg_getsec(srtp, SECTION_ZRTP_NAME);
                if(!zrtp) {
                    media_if.srtp->zrtp_enable = false;
                } else {
                    media_if.srtp->zrtp_enable = true;
                    for(unsigned int i = 0; i < cfg_size(zrtp, PARAM_HASHES_NAME); i++) {
                        std::string hash = cfg_getnstr(zrtp, PARAM_HASHES_NAME, i);
                        int ihash = media_if.zrtp_hash_from_str(hash);
                        if(!ihash) {
                            ERROR("incorrect or not supported zrtp hash name %s", hash.c_str());
                            return -1;
                        }
                        media_if.srtp->zrtp_hashes.push_back(ihash);
                    }
                    for(unsigned int i = 0; i < cfg_size(zrtp, PARAM_CIPHERS_NAME); i++) {
                        std::string cipher = cfg_getnstr(zrtp, PARAM_CIPHERS_NAME, i);
                        int icipher = media_if.zrtp_cipher_from_str(cipher);
                        if(!icipher) {
                            ERROR("incorrect or not supported zrtp cipher name %s", cipher.c_str());
                            return -1;
                        }
                        media_if.srtp->zrtp_ciphers.push_back(icipher);
                    }
                    for(unsigned int i = 0; i < cfg_size(zrtp, PARAM_AUTHTAGS_NAME); i++) {
                        std::string authtag = cfg_getnstr(zrtp, PARAM_AUTHTAGS_NAME, i);
                        int iauthtag = media_if.zrtp_authtag_from_str(authtag);
                        if(!iauthtag) {
                            ERROR("incorrect or not supported zrtp authtag name %s", authtag.c_str());
                            return -1;
                        }
                        media_if.srtp->zrtp_authtags.push_back(iauthtag);
                    }
                    for(unsigned int i = 0; i < cfg_size(zrtp, PARAM_DHMODES_NAME); i++) {
                        std::string dhmode = cfg_getnstr(zrtp, PARAM_DHMODES_NAME, i);
                        int idhmode = media_if.zrtp_dhmode_from_str(dhmode);
                        if(!idhmode) {
                            ERROR("incorrect or not supported zrtp dhmode name %s", dhmode.c_str());
                            return -1;
                        }
                        media_if.srtp->zrtp_dhmodes.push_back(idhmode);
                    }
                    for(unsigned int i = 0; i < cfg_size(zrtp, PARAM_SAS_NAME); i++) {
                        std::string sas = cfg_getnstr(zrtp, PARAM_SAS_NAME, i);
                        int isas= media_if.zrtp_sas_from_str(sas);
                        if(!isas) {
                            ERROR("incorrect or not supported zrtp sas name %s", sas.c_str());
                            return -1;
                        }
                        media_if.srtp->zrtp_sas.push_back(isas);
                    }
                }

                cfg_t* dtls = cfg_getsec(srtp, SECTION_DTLS_NAME);
                if(!dtls) {
                    media_if.srtp->dtls_enable = false;
                } else {
                    media_if.srtp->dtls_enable = true;
                    cfg_t* server = cfg_getsec(dtls, SECTION_SERVER_NAME);
                    if(!server) {
                        ERROR("absent mandatory section 'server' in dtls configuration");
                        return -1;
                    }
                    for(unsigned int i = 0; i < cfg_size(server, PARAM_PROTOCOLS_NAME); i++) {
                        std::string protocol = cfg_getnstr(server, PARAM_PROTOCOLS_NAME, i);
                        media_if.srtp->server_settings.protocols.push_back(dtls_settings::protocolFromStr(protocol));
                    }
                    for(unsigned int i = 0; i < cfg_size(server, PARAM_PROFILES_NAME); i++) {
                        media_if.srtp->server_settings.srtp_profiles.push_back(SdpCrypto::str2profile(cfg_getnstr(server, PARAM_PROFILES_NAME, i)));
                    }
                    if(getMandatoryParameter(server, PARAM_CERTIFICATE_NAME, media_if.srtp->server_settings.certificate_path) ||
                    getMandatoryParameter(server, PARAM_CERTIFICATE_KEY_NAME, media_if.srtp->server_settings.certificate_key_path)){
                        return -1;
                    }
                    for(unsigned int i = 0; i < cfg_size(server, PARAM_CIPHERS_NAME); i++) {
                        std::string cipher = cfg_getnstr(server, PARAM_CIPHERS_NAME, i);
                        media_if.srtp->server_settings.cipher_list.push_back(cipher);
                    }
                    for(unsigned int i = 0; i < cfg_size(server, PARAM_MACS_NAME); i++) {
                        std::string mac = cfg_getnstr(server, PARAM_MACS_NAME, i);
                        media_if.srtp->server_settings.macs_list.push_back(mac);
                    }
                    media_if.srtp->server_settings.verify_client_certificate = cfg_getbool(server, PARAM_VERIFY_CERT_NAME);
                    media_if.srtp->server_settings.require_client_certificate = true;
                    media_if.srtp->server_settings.dhparam = cfg_getstr(server, PARAM_DH_PARAM_NAME);
                    for(unsigned int i = 0; i < cfg_size(server, PARAM_CA_LIST_NAME); i++) {
                        std::string ca = cfg_getnstr(server, PARAM_CA_LIST_NAME, i);
                        media_if.srtp->server_settings.ca_path_list.push_back(ca);
                    }

                    if(media_if.srtp->server_settings.verify_client_certificate && !media_if.srtp->server_settings.require_client_certificate) {
                        ERROR("incorrect server tls configuration for interface %s: verify client certificate cannot be set, if clients certificate is not required", media_if.name.c_str());
                        return -1;
                    }

                    cfg_t* client = cfg_getsec(dtls, SECTION_CLIENT_NAME);
                    if(!client) {
                        ERROR("absent mandatory section 'client' in dtls configuration");
                        return -1;
                    }
                    for(unsigned int i = 0; i < cfg_size(client, PARAM_PROTOCOLS_NAME); i++) {
                        std::string protocol = cfg_getnstr(client, PARAM_PROTOCOLS_NAME, i);
                        media_if.srtp->client_settings.protocols.push_back(dtls_settings::protocolFromStr(protocol));
                    }
                    for(unsigned int i = 0; i < cfg_size(client, PARAM_PROFILES_NAME); i++) {
                        media_if.srtp->client_settings.srtp_profiles.push_back(SdpCrypto::str2profile(cfg_getnstr(client, PARAM_PROFILES_NAME, i)));
                    }
                    media_if.srtp->client_settings.certificate_path = cfg_getstr(client, PARAM_CERTIFICATE_NAME);
                    media_if.srtp->client_settings.certificate_key_path = cfg_getstr(client, PARAM_CERTIFICATE_KEY_NAME);
                    media_if.srtp->client_settings.verify_certificate_chain = cfg_getbool(client, PARAM_CERT_CHAIN_NAME);
                    media_if.srtp->client_settings.verify_certificate_cn = cfg_getbool(client, PARAM_CERT_CN_NAME);
                    for(unsigned int i = 0; i < cfg_size(client, PARAM_CA_LIST_NAME); i++) {
                        std::string ca = cfg_getnstr(client, PARAM_CA_LIST_NAME, i);
                        media_if.srtp->client_settings.ca_path_list.push_back(ca);
                    }
                }
            }
        }
        if(cfg_size(if_, SECTION_IP4_NAME)) {
            cfg_t* ip4 = cfg_getsec(if_, SECTION_IP4_NAME);
            if(cfg_size(ip4, SECTION_RTP_NAME)) {
                cfg_t* cfg = cfg_getsec(ip4, SECTION_RTP_NAME);
                MEDIA_info* info =  dynamic_cast<MEDIA_info*>(readInterface(cfg, media_if.name, AT_V4));
                if(!info) {
                    return -1;
                }
                media_if.proto_info.push_back(info);
            }
            if(cfg_size(ip4, SECTION_RTSP_NAME)) {
                cfg_t* cfg = cfg_getsec(ip4, SECTION_RTSP_NAME);
                MEDIA_info* info = dynamic_cast<MEDIA_info*>(readInterface(cfg, media_if.name, AT_V4));
                if(!info) {
                    return -1;
                }
                media_if.proto_info.push_back(info);
            }
        }
        if(cfg_size(if_, SECTION_IP6_NAME)) {
            cfg_t* ip4 = cfg_getsec(if_, SECTION_IP6_NAME);
            if(cfg_size(ip4, SECTION_RTP_NAME)) {
                cfg_t* cfg = cfg_getsec(ip4, SECTION_RTP_NAME);
                MEDIA_info* info = dynamic_cast<MEDIA_info*>(readInterface(cfg, media_if.name, AT_V6));
                if(!info) {
                    return -1;
                }
                media_if.proto_info.push_back(info);
            }
            if(cfg_size(ip4, SECTION_RTSP_NAME)) {
                cfg_t* cfg = cfg_getsec(ip4, SECTION_RTSP_NAME);
                MEDIA_info* info = dynamic_cast<MEDIA_info*>(readInterface(cfg, media_if.name, AT_V6));
                if(!info) {
                    return -1;
                }
                media_if.proto_info.push_back(info);
            }
        }
        if(media_if.proto_info.empty()) {
            config->media_ifs.pop_back();
        } else {
            for(auto &self_p : media_if.proto_info) {
                //check public domain is resolvable locally
                if(!self_p->public_domain.empty()) {
                    dns_handle dh;
                    dns_priority priority =  self_p->type_ip == AT_V4 ? IPv4_only : IPv6_only;
                    sockaddr_storage a;
                    if (resolver::instance()->resolve_name(self_p->public_domain.data(),
                        &dh,&a, priority) < 0)
                    {
                        WARN("failed to resolve domain: '%s' with priority %s "
                             "(media interface '%s', transport: %s, protocol: %s)",
                             self_p->public_domain.data(),
                             dns_priority_str(priority),
                             media_if.name.data(),
                             self_p->transportToStr().data(),
                             self_p->ipTypeToStr().data());
                    }
                }
                //check for ports overlapping
                for(auto &i : config->media_ifs) {
                    if(&i == &media_if)
                        continue;
                    for(auto &p : i.proto_info) {
                        if(p->type_ip != self_p->type_ip)
                            continue;
                        if(p->local_ip != self_p->local_ip)
                            continue;
                        if(self_p->low_port <= p->high_port &&
                           p->low_port <= self_p->high_port)
                        {
                            ERROR("media interface '%s' with range (%hu-%hu) for %s %s "
                                  "overlaps ports range for interface '%s' with range (%hu-%hu)",
                                  media_if.name.data(),
                                  self_p->low_port, self_p->high_port,
                                  self_p->ipTypeToStr().data(), self_p->local_ip.data(),
                                  i.name.data(), p->low_port, p->high_port);
                            return -1;
                        }
                    }
                }
            }
        }
    }
    return 0;
}

IP_info* AmLcConfig::readInterface(cfg_t* cfg, const std::string& if_name, AddressType ip_type)
{
    IP_info* info;
    SIP_info* sinfo = nullptr;
    SIP_UDP_info* suinfo = nullptr;
    SIP_TCP_info* stinfo = nullptr;
    SIP_TLS_info* stlinfo = nullptr;
    WS_info* wsinfo = nullptr;
    MEDIA_info* mediainfo = nullptr;
    RTP_info* rtpinfo = nullptr;

    if(strcmp(cfg->name, SECTION_SIP_UDP_NAME) == 0) {
        info = sinfo = suinfo = new SIP_UDP_info();
    } else if(strcmp(cfg->name, SECTION_SIP_TCP_NAME) == 0) {
        info = sinfo = stinfo = new SIP_TCP_info();
    } else if(strcmp(cfg->name, SECTION_SIP_TLS_NAME) == 0) {
        info = sinfo = stinfo = stlinfo = new SIP_TLS_info();
    } else if(strcmp(cfg->name, SECTION_SIP_WS_NAME) == 0) {
        SIP_WS_info *pinfo = new SIP_WS_info();
        info = sinfo = stinfo = static_cast<SIP_TCP_info*>(pinfo);
        wsinfo = static_cast<WS_info*>(pinfo);
    } else if(strcmp(cfg->name, SECTION_SIP_WSS_NAME) == 0) {
        SIP_WSS_info *pinfo = new SIP_WSS_info();
        info = sinfo = stinfo = stlinfo = static_cast<SIP_TLS_info*>(pinfo);
        wsinfo = static_cast<WS_info*>(pinfo);
    } else if(strcmp(cfg->name, SECTION_RTP_NAME) == 0) {
        info = mediainfo = rtpinfo = new RTP_info();
    } else if(strcmp(cfg->name, SECTION_RTSP_NAME) == 0) {
        info = mediainfo = new RTSP_info();
    } else {
        return nullptr;
    }

    //common opts
    info->type_ip = ip_type;
    if(getMandatoryParameter(cfg, PARAM_ADDRESS_NAME, info->local_ip)) {
        return nullptr;
    }
    if(cfg_size(cfg, PARAM_PUBLIC_ADDR_NAME)) {
        info->public_ip = cfg_getstr(cfg, PARAM_PUBLIC_ADDR_NAME);
    }
    if(cfg_size(cfg, PARAM_PUBLIC_DOMAIN_NAME)) {
        info->public_domain = cfg_getstr(cfg, PARAM_PUBLIC_DOMAIN_NAME);
    }

    info->sig_sock_opts |=  cfg_getbool(cfg, PARAM_USE_RAW_NAME) ? trsp_socket::use_raw_sockets : 0;
    info->sig_sock_opts |=  cfg_getbool(cfg, PARAM_FORCE_OBD_IF_NAME) ? trsp_socket::force_outbound_if : 0;
    info->sig_sock_opts |=  cfg_getbool(cfg, PARAM_FORCE_VIA_PORT_NAME) ? trsp_socket::force_via_address : 0;
    info->sig_sock_opts |=  cfg_getbool(cfg, PARAM_STAT_CL_PORT_NAME) ? trsp_socket::static_client_port : 0;

    if(cfg_size(cfg, PARAM_DSCP_NAME)) {
        info->dscp = static_cast<uint8_t>(cfg_getint(cfg, PARAM_DSCP_NAME));
        info->tos_byte = info->dscp << 2;
    }

    //MEDIA specific opts
    if(mediainfo) {
        if(getMandatoryParameter(cfg, PARAM_HIGH_PORT_NAME, mediainfo->high_port) ||
           getMandatoryParameter(cfg, PARAM_LOW_PORT_NAME, mediainfo->low_port)) {
            return nullptr;
        }
    }

    //RTP specific opts
    if(rtpinfo) {
        rtpinfo->addMediaAddress(rtpinfo->local_ip);
        for(unsigned int i = 0; i < cfg_size(cfg, PARAM_ADDITIONAL_ADDR_NAME); i++) {
            string address = cfg_getnstr(cfg, PARAM_ADDITIONAL_ADDR_NAME, i);
            if((rtpinfo->type_ip == AT_V4 && validate_ip4(address)) ||
               (rtpinfo->type_ip == AT_V6 && validate_ip6(address)))
                return nullptr;
            rtpinfo->addMediaAddress(address);
        }
    }

    //MEDIA specific opts
    if(mediainfo) {
        if(mediainfo->prepare(if_name))
            return nullptr;
    }

    //SIP specific opts
    if(sinfo) {
        info->announce_port = cfg_getbool(cfg, PARAM_ANNOUNCE_PORT_NAME);

        if(getMandatoryParameter(cfg, PARAM_PORT_NAME, sinfo->local_port)) {
            return nullptr;
        }
        info->sig_sock_opts |=  cfg_getbool(cfg, PARAM_FORCE_TRANSPORT_NAME) ? 0 : trsp_socket::no_transport_in_contact;

        if(cfg_size(cfg, SECTION_ORIGACL_NAME)) {
            cfg_t* acl = cfg_getsec(cfg, SECTION_ORIGACL_NAME);
            if(readAcl(acl, sinfo->acls.inv, if_name)) {
                 ERROR("error parsing invite acl for interface: %s",if_name.c_str());
                 return nullptr;
            }
        }

        if(cfg_size(cfg, SECTION_OPT_NAME)) {
            cfg_t* opt_acl = cfg_getsec(cfg, SECTION_OPT_NAME);
            if(readAcl(opt_acl, sinfo->acls.opt, if_name)) {
                ERROR("error parsing options acl for interface: %s",if_name.c_str());
                return nullptr;
            }
        }

        if(cfg_size(cfg, SECTION_REG_ACL_NAME)) {
            cfg_t* reg_acl = cfg_getsec(cfg, SECTION_REG_ACL_NAME);
            if(readAcl(reg_acl, sinfo->acls.reg, if_name)) {
                ERROR("error parsing register acl for interface: %s",if_name.c_str());
                return nullptr;
            }
        }
    }

    //TCP specific opts
    if(stinfo) {
        stinfo->tcp_connect_timeout = cuint(cfg_getint(cfg, PARAM_CONNECT_TIMEOUT_NAME));
        stinfo->tcp_idle_timeout = cuint(cfg_getint(cfg, PARAM_IDLE_TIMEOUT_NAME));
    }

    //TLS specific opts
    if(stlinfo) {
        cfg_t* server = cfg_getsec(cfg, SECTION_SERVER_NAME);
        if(!server) {
            ERROR("absent mandatory section 'server' in tls configuration");
            return nullptr;
        }
        for(unsigned int i = 0; i < cfg_size(server, PARAM_PROTOCOLS_NAME); i++) {
            std::string protocol = cfg_getnstr(server, PARAM_PROTOCOLS_NAME, i);
            stlinfo->server_settings.protocols.push_back(tls_settings::protocolFromStr(protocol));
        }
        if(getMandatoryParameter(server, PARAM_CERTIFICATE_NAME, stlinfo->server_settings.certificate_path) ||
           getMandatoryParameter(server, PARAM_CERTIFICATE_KEY_NAME, stlinfo->server_settings.certificate_key_path)) {
            return nullptr;
        }
        for(unsigned int i = 0; i < cfg_size(server, PARAM_CIPHERS_NAME); i++) {
            std::string cipher = cfg_getnstr(server, PARAM_CIPHERS_NAME, i);
            stlinfo->server_settings.cipher_list.push_back(cipher);
        }
        for(unsigned int i = 0; i < cfg_size(server, PARAM_MACS_NAME); i++) {
            std::string mac = cfg_getnstr(server, PARAM_MACS_NAME, i);
            stlinfo->server_settings.macs_list.push_back(mac);
        }
        stlinfo->server_settings.verify_client_certificate = cfg_getbool(server, PARAM_VERIFY_CERT_NAME);
        stlinfo->server_settings.require_client_certificate = cfg_getbool(server, PARAM_REQUIRE_CERT_NAME);
        stlinfo->server_settings.dhparam = cfg_getstr(server, PARAM_DH_PARAM_NAME);
        for(unsigned int i = 0; i < cfg_size(server, PARAM_CA_LIST_NAME); i++) {
            std::string ca = cfg_getnstr(server, PARAM_CA_LIST_NAME, i);
            stlinfo->server_settings.ca_path_list.push_back(ca);
        }

        if(stlinfo->server_settings.verify_client_certificate && !stlinfo->server_settings.require_client_certificate) {
            ERROR("incorrect server tls configuration for interface %s: verify client certificate cannot be set, if clients certificate is not required", if_name.c_str());
            return nullptr;
        }

        cfg_t* client = cfg_getsec(cfg, SECTION_CLIENT_NAME);
        if(!client) {
            ERROR("absent mandatory section 'client' in tls configuration");
            return nullptr;
        }
        for(unsigned int i = 0; i < cfg_size(client, PARAM_PROTOCOLS_NAME); i++) {
            std::string protocol = cfg_getnstr(client, PARAM_PROTOCOLS_NAME, i);
            stlinfo->client_settings.protocols.push_back(tls_settings::protocolFromStr(protocol));
        }
        stlinfo->client_settings.certificate_path = cfg_getstr(client, PARAM_CERTIFICATE_NAME);
        stlinfo->client_settings.certificate_key_path = cfg_getstr(client, PARAM_CERTIFICATE_KEY_NAME);
        stlinfo->client_settings.verify_certificate_chain = cfg_getbool(client, PARAM_CERT_CHAIN_NAME);
        stlinfo->client_settings.verify_certificate_cn = cfg_getbool(client, PARAM_CERT_CN_NAME);
        for(unsigned int i = 0; i < cfg_size(client, PARAM_CA_LIST_NAME); i++) {
            std::string ca = cfg_getnstr(client, PARAM_CA_LIST_NAME, i);
            stlinfo->client_settings.ca_path_list.push_back(ca);
        }
    }

    if(wsinfo) {
        wsinfo->cors_mode = cfg_getbool(cfg, PARAM_CORS_MODE_NAME);
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

int AmLcConfig::finalizeIpConfig(ConfigContainer* config)
{
    fillSysIntfList(config);

    for(auto if_iterator = config->sip_ifs.begin(); if_iterator != config->sip_ifs.end(); if_iterator++) {
        auto if_names_iterator = config->sip_if_names.find(if_iterator->name);
        if(if_names_iterator != config->sip_if_names.end()) {
            WARN("duplicate sip name interface %s", if_iterator->name.c_str());
            config->sip_if_names[if_iterator->name] =
                static_cast<unsigned short>(if_iterator - config->sip_ifs.begin());
        } else {
            config->sip_if_names.insert(std::make_pair(
                if_iterator->name,
                static_cast<unsigned short>(if_iterator - config->sip_ifs.begin())));
        }

        unsigned short i = 0;
        for(auto& info : if_iterator->proto_info) {
            std::string local_ip = info->local_ip;
            //IPv6 reference in local_ip will be ensured by insertSIPInterfaceMapping
            info->local_ip = fixIface2IP(info->local_ip, false);
            if(info->local_ip.empty()) {
                ERROR("could not determine signaling IP %s for "
                      "interface '%s'\n", local_ip.c_str(), if_iterator->name.c_str());
                return -1;
            }
            if (insertSIPInterfaceMapping(config, *info,cint(if_iterator - config->sip_ifs.begin())) < 0 ||
                (*if_iterator).insertProtoMapping(*info, i) ||
                setNetInterface(config, *info))
            {
                return -1;
            }

            SIP_TLS_info* tls_info = SIP_TLS_info::toSIP_TLS(info);
            if(tls_info) {
                if(!tls_info->client_settings.checkCertificateAndKey(
                        if_iterator->name.c_str(),"SIP","client") ||
                    !tls_info->server_settings.checkCertificateAndKey(
                        if_iterator->name.c_str(),"SIP","server"))
                {
                    return -1;
                }

                tls_info->client_settings.initNotAfterCounter()
                    .addLabel("interface", if_iterator->name)
                    .addLabel("protocol", tls_info->ipTypeToStr())
                    .addLabel("transport", tls_info->transportToStr())
                    .addLabel("role", "client");

                tls_info->server_settings.initNotAfterCounter()
                    .addLabel("interface", if_iterator->name)
                    .addLabel("protocol", tls_info->ipTypeToStr())
                    .addLabel("transport", tls_info->transportToStr())
                    .addLabel("role", "server");

                tls_info->client_settings.load_certificates();
                tls_info->server_settings.load_certificates();
            }
            i++;
        }
    }

    for(auto if_iterator = config->media_ifs.begin(); if_iterator != config->media_ifs.end(); if_iterator++) {
        auto if_names_iterator = config->media_if_names.find(if_iterator->name);
        if(if_names_iterator != config->media_if_names.end()) {
            WARN("duplicate media name interface %s", if_iterator->name.c_str());
            config->media_if_names[if_iterator->name] =
                static_cast<unsigned short>(if_iterator - config->media_ifs.begin());
        } else {
            config->media_if_names.insert(std::make_pair(
                if_iterator->name,
                static_cast<unsigned short>(if_iterator - config->media_ifs.begin())));
        }

        if(if_iterator->srtp->dtls_enable) {
            if(!if_iterator->srtp->client_settings.checkCertificateAndKey(
                    if_iterator->name.c_str(),"media","client") ||
                !if_iterator->srtp->server_settings.checkCertificateAndKey(
                    if_iterator->name.c_str(),"media","server"))
            {
                return -1;
            }

            if_iterator->srtp->client_settings.initNotAfterCounter()
                .addLabel("interface", if_iterator->name)
                .addLabel("role", "client");

            if_iterator->srtp->server_settings.initNotAfterCounter()
                .addLabel("interface", if_iterator->name)
                .addLabel("role", "server");

            if_iterator->srtp->client_settings.load_certificates();
            if_iterator->srtp->server_settings.load_certificates();
        }

        unsigned short i = 0;
        for(auto& info : if_iterator->proto_info) {
            std::string local_ip = info->local_ip;
            info->local_ip = fixIface2IP(info->local_ip, true);
            if(info->local_ip.empty()) {
                ERROR("could not determine signaling IP %s for "
                      "interface '%s'\n", local_ip.c_str(), if_iterator->name.c_str());
                return -1;
            }
            if ((*if_iterator).insertProtoMapping(*info, i) ||
                setNetInterface(config, *info)) {
                return -1;
            }

            i++;
        }
    }

    fillMissingLocalSIPIPfromSysIntfs(config);
    return 0;
}

void AmLcConfig::fillMissingLocalSIPIPfromSysIntfs(ConfigContainer* config)
{
    // add addresses from SysIntfList, if not present
    for(unsigned int idx = 0; idx < config->sip_ifs.size(); idx++) {
        std::vector<SIP_info*>::iterator info_it = config->sip_ifs[idx].proto_info.begin();
        for(;info_it != config->sip_ifs[idx].proto_info.end(); info_it++) {
            std::vector<SysIntf>::iterator intf_it = config->sys_ifs.begin();
            for(; intf_it != config->sys_ifs.end(); ++intf_it) {

                std::list<IPAddr>::iterator addr_it = intf_it->addrs.begin();
                for(; addr_it != intf_it->addrs.end(); addr_it++) {
                    if(*addr_it == (*info_it)->local_ip) {
                        break;
                    }
                }

                // address not in this interface
                if(addr_it == intf_it->addrs.end())
                    continue;

                // address is primary
                if(addr_it == intf_it->addrs.begin())
                    continue;

                if(config->local_sip_ip2if.find(intf_it->addrs.front().addr) == config->local_sip_ip2if.end()) {
                    DBG("mapping unmapped IP address '%s' to interface #%u ",
                        intf_it->addrs.front().addr.c_str(), idx);
                    config->local_sip_ip2if[intf_it->addrs.front().addr] =
                        static_cast<unsigned short>(idx);
                }
            }
        }
    }
}

int AmLcConfig::setNetInterface(ConfigContainer* config, IP_info& ip_if)
{
    for(unsigned int i=0; i < config->sys_ifs.size(); i++) {
        std::list<IPAddr>::iterator addr_it = config->sys_ifs[i].addrs.begin();
        while(addr_it != config->sys_ifs[i].addrs.end()) {
            if(*addr_it == ip_if.local_ip) {
                ip_if.net_if = config->sys_ifs[i].name;
                ip_if.net_if_idx = i;
                return 0;
            }
            addr_it++;
        }
    }
    ERROR("failed to find interface with address: %s",
          ip_if.local_ip.c_str());
    return -1;
}

int AmLcConfig::insertSIPInterfaceMapping(ConfigContainer* config, SIP_info& intf, int idx) {
    if(config->local_sip_ip2if.find(intf.local_ip) == config->local_sip_ip2if.end()
       || intf.local_port == 5060) // when two interfaces on the same IP
    {                              // the one with port 5060 has priority
        config->local_sip_ip2if.emplace(intf.local_ip,idx);
        //convert to IPv6 reference
        ensure_ipv6_reference(intf.local_ip);
        //add mapping for IPv6 reference as well
        config->local_sip_ip2if.emplace(intf.local_ip,idx);
    } else {
        ensure_ipv6_reference(intf.local_ip);
    }
    return 0;
}

std::string AmLcConfig::fixIface2IP(const std::string& dev_name, bool v6_for_sip, ConfigContainer* config)
{
    struct sockaddr_storage ss;
    if(am_inet_pton(dev_name.c_str(), &ss)) {
        if(v6_for_sip && (ss.ss_family == AF_INET6) && (dev_name[0] != '['))
            return "[" + dev_name + "]";
        else
            return dev_name;
    }

    for(std::vector<SysIntf>::iterator intf_it = config->sys_ifs.begin();
            intf_it != config->sys_ifs.end(); ++intf_it) {

        if(intf_it->name != dev_name)
            continue;

        if(intf_it->addrs.empty()) {
            ERROR("No IP address for interface '%s'",intf_it->name.c_str());
            return "";
        }

        DBG("dev_name = '%s'",dev_name.c_str());
        return intf_it->addrs.front().addr;
    }

    return "";
}

int AmLcConfig::setLogLevel(const std::string& level, bool apply)
{
    int n;
    if(-1==(n = parse_log_level(level).value_or(-1)))
        return 0;
    log_level = static_cast<Log_Level>(n);
    if (apply)
        set_log_level(log_level);
    return 1;
}

int AmLcConfig::setStderrLogLevel(const std::string& level, bool apply)
{
    int n;
    if(-1==(n = parse_log_level(level).value_or(-1)))
        return 0;
    log_level = static_cast<Log_Level>(n);
    if (apply && m_config.log_stderr)
        set_stderr_log_level(log_level);
    return 1;
}

int AmLcConfig::setLogStderr(bool s, bool apply)
{
  if (s) {
    if(apply && !m_config.log_stderr)
      register_stderr_facility();
    m_config.log_stderr = true;
  } else if (!s) {
    //deny to disable previously enabled stderr logging
  } else {
    return 0;
  }
  return 1;
}

/** Get the list of network interfaces with the associated addresses & flags */
bool AmLcConfig::fillSysIntfList(ConfigContainer* config)
{
    struct ifaddrs *ifap = nullptr;

    // socket to grab MTU
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) {
        ERROR("socket() failed: %s",strerror(errno));
        return false;
    }
    SOCKET_LOG("socket(AF_INET, SOCK_DGRAM, 0) = %d", fd);

    if(getifaddrs(&ifap) < 0) {
        ERROR("getifaddrs() failed: %s",strerror(errno));
        return false;
    }

    char host[NI_MAXHOST];
    for(struct ifaddrs *p_if = ifap; p_if != nullptr; p_if = p_if->ifa_next) {
        if(p_if->ifa_addr == nullptr)
            continue;

        if( (p_if->ifa_addr->sa_family != AF_INET) &&
                (p_if->ifa_addr->sa_family != AF_INET6) )
            continue;

        if(!(p_if->ifa_flags & IFF_UP))
            continue;

        if(p_if->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *addr = reinterpret_cast<struct sockaddr_in6 *>(p_if->ifa_addr);
            if(IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
                // sorry, we don't support link-local addresses...
                continue;

                // convert address from kernel-style to userland
                // addr->sin6_scope_id = ntohs(*(uint16_t *)&addr->sin6_addr.s6_addr[2]);
                // addr->sin6_addr.s6_addr[2] = addr->sin6_addr.s6_addr[3] = 0;
            }
        }

        if (am_inet_ntop(reinterpret_cast<const sockaddr_storage*>(p_if->ifa_addr), host, NI_MAXHOST) == nullptr) {
            ERROR("am_inet_ntop() failed");
            continue;
            // freeifaddrs(ifap);
            // return false;
        }

        string iface_name(p_if->ifa_name);
        std::vector<SysIntf>::iterator intf_it;
        for(intf_it = config->sys_ifs.begin(); intf_it != config->sys_ifs.end(); ++intf_it) {
            if(intf_it->name == iface_name)
                break;
        }

        if(intf_it == config->sys_ifs.end()) {
            unsigned int sys_if_idx = if_nametoindex(iface_name.c_str());
            if(config->sys_ifs.size() < sys_if_idx+1) {
                config->sys_ifs.resize(sys_if_idx+1);
                intf_it = config->sys_ifs.end() - 1;
            }

            intf_it = config->sys_ifs.begin() + sys_if_idx;
            intf_it->name  = iface_name;
            intf_it->flags = p_if->ifa_flags;

            struct ifreq ifr;
            strncpy(ifr.ifr_name,p_if->ifa_name,IFNAMSIZ-1);

            if (ioctl(fd, SIOCGIFMTU, &ifr) < 0 ) {
                ERROR("ioctl: %s",strerror(errno));
                ERROR("setting MTU for this interface to default (1500)");
                intf_it->mtu = 1500;
            }
            else {
                intf_it->mtu = cuint(ifr.ifr_mtu);
            }
        }

        DBG3("iface='%s';ip='%s';flags=0x%x",p_if->ifa_name,host,p_if->ifa_flags);
        intf_it->addrs.push_back(IPAddr(fixIface2IP(host, true),
            static_cast<short>(p_if->ifa_addr->sa_family)));
    }

    freeifaddrs(ifap);
    close(fd);

    return true;
}

int AmLcConfig::checkSipInterfaces(ConfigContainer* config)
{
    std::vector< std::tuple<SIP_interface *,SIP_info*> > infos;

    for(auto& sip_if : config->sip_ifs) {
        bool bfind = false;
        for(auto& media_if : config->media_ifs) {
            if(sip_if.default_media_if == media_if.name) {
                bfind = true;
            }
        }

        if(!bfind) {
            ERROR("default media interface for sip interface \'%s\' is absent", sip_if.name.c_str());
            return -1;
        }

        for(auto& info : sip_if.proto_info) {
            for(auto& other_info_tuple : infos) {
                auto &other_sip_if  = *std::get<0>(other_info_tuple);
                auto &other_info  = *std::get<1>(other_info_tuple);

                if(info->local_ip == other_info.local_ip &&
                   info->local_port == other_info.local_port &&
                   (info->type == other_info.type ||
                    (info->type > SIP_info::UDP && other_info.type > SIP_info::UDP)))
                {
                    ERROR("duplicate ip/port %s/%d in interfaces %s/%s and %s/%s",
                        other_info.local_ip.c_str(),
                        other_info.local_port,
                        sip_if.name.c_str(), info->transportToStr().c_str(),
                        other_sip_if.name.c_str(), other_info.transportToStr().c_str());
                        return -1;
                }
            }

            infos.emplace_back(&sip_if, const_cast<SIP_info*>(info));
        }
    }

    return 0;
}

#define checkMandatoryParameter(cfg, ifname) if(!cfg_size(cfg, ifname.c_str())) { \
                                                ERROR("absent mandatory parameter %s in section %s", ifname.c_str(), cfg->name);\
                                                return -1;\
                                             }

int AmLcConfig::getMandatoryParameter(cfg_t* cfg, const std::string& if_name, std::string& data)
{
    checkMandatoryParameter(cfg, if_name);
    data = cfg_getstr(cfg, if_name.c_str());
    return 0;
}

int AmLcConfig::getMandatoryParameter(cfg_t* cfg, const std::string& if_name, int& data)
{
    checkMandatoryParameter(cfg, if_name);
    data = cint(cfg_getint(cfg, if_name.c_str()));
    return 0;
}

int AmLcConfig::getMandatoryParameter(cfg_t* cfg, const std::string& if_name, unsigned int& data)
{
    checkMandatoryParameter(cfg, if_name);
    data = cuint(cfg_getint(cfg, if_name.c_str()));
    return 0;
}

int AmLcConfig::getMandatoryParameter(cfg_t* cfg, const std::string& if_name, unsigned short& data)
{
    checkMandatoryParameter(cfg, if_name);
    data = static_cast<unsigned short>(cfg_getint(cfg, if_name.c_str()));
    return 0;
}

int AmLcConfig::getMandatoryParameter(cfg_t* cfg, const std::string& if_name, bool& data)
{
    checkMandatoryParameter(cfg, if_name);
    data = cfg_getbool(cfg, if_name.c_str());
    return 0;
}

std::string AmLcConfig::serialize()
{
    std::string ret;

    size_t l;
    char *buf;
    FILE *f = open_memstream(&buf,&l);

    if(!f) {
        return std::string("failed to allocate memory stream");
    }

    if(m_cfg)
        cfg_print(m_cfg, f);
    fclose(f);

    ret = std::string(buf,l);
    free(buf);

    return ret;
}

void AmLcConfig::applySignature(const char *signature, bool override)
{
    if(!override && !is_default_signature && !signature_header_uac.empty()) {
        //ignore if already initialized with non-default signature
        return;
    }

    if(!signature) {
        signature = DEFAULT_SIGNATURE;
        is_default_signature = true;
    } else {
        is_default_signature = false;
    }

    signature_header_uac = string(SIP_HDR_COLSP(SIP_HDR_USER_AGENT)) + signature + CRLF;
    signature_header_uas = string(SIP_HDR_COLSP(SIP_HDR_SERVER)) + signature + CRLF;
}

void AmLcConfig::addSignatureHdr(AmSipRequest &req) const
{
    if(!signature_header_uac.empty())
        req.hdrs += signature_header_uac;
}

void AmLcConfig::addSignatureHdr(AmSipReply &reply) const
{
    if(!signature_header_uas.empty())
        reply.hdrs += signature_header_uas;
}

int AmLcConfig::addUacSignature(char *buf) const
{
    memcpy(buf, signature_header_uac.data(), signature_header_uac.size());
    return signature_header_uac.size();
}

int AmLcConfig::getUacSignatureLen() const {
    return signature_header_uac.size();
}

int AmLcConfig::addUasSignature(char *buf) const
{
    memcpy(buf, signature_header_uas.data(), signature_header_uas.size());
    return signature_header_uas.size();
}

int AmLcConfig::getUasSignatureLen() const {
    return signature_header_uas.size();
}

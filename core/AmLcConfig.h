#ifndef AM_LC_CONFIG_H
#define AM_LC_CONFIG_H

#include <confuse.h>
#include <map>
#include "AmLCContainers.h"
#include "AmDtmfDetector.h"
#include "Am100rel.h"
#include "AmAudio.h"
#include "AmUtils.h"
#include "ShutdownHandlersProcessor.h"

#define VALUE_LOG_NO                 "no"
#define VALUE_LOG_DEBUG              "debug"
#define VALUE_LOG_ERR                "error"
#define VALUE_LOG_WARN               "warn"
#define VALUE_LOG_INFO               "info"

extern int validate_log_func(cfg_t *cfg, cfg_opt_t *opt);
extern int parse_log_level(const std::string& level);

#define AmConfig AmLcConfig::instance().m_config

struct ConfigContainer
{
    ConfigContainer();
    std::vector<SIP_interface> sip_ifs;

    std::vector<MEDIA_interface> media_ifs;
    MEDIA_info &getMediaProtoInfo(int iface_ifx, int proto_idx) {
        return *media_ifs[static_cast<size_t>(iface_ifx)]
            .proto_info[static_cast<size_t>(proto_idx)];
    }
    MEDIA_interface &getMediaIfaceInfo(int iface_ifx) {
        return media_ifs[static_cast<size_t>(iface_ifx)];
    }

    std::map<std::string, unsigned short> sip_if_names;
    std::map<std::string, unsigned short> media_if_names;
    std::map<std::string,unsigned short> local_sip_ip2if;
    std::vector<SysIntf> sys_ifs;

    enum ApplicationSelector {
        App_RURIUSER,
        App_RURIPARAM,
        App_APPHDR,
        App_MAPPING,
        App_SPECIFIED
    };

    enum SymmetricRtpMode {
        SM_RTP_PACKETS,
        SM_RTP_DELAY
    };

    std::string register_application;
    std::string options_application;
    struct app_selector {
        std::string application;
        /** this is regex->application mapping is used if  App_MAPPING */
        RegexMappingVector app_mapping;
        /** type of application selection (parsed from Application) */
        ApplicationSelector app_select;
    };

    std::vector<app_selector> applications;

    std::vector<std::string> modules;
    std::map<std::string, std::string> module_config;
    std::set<string> rtld_global_plugins;
    std::string modules_path;
    std::string configs_path;
    std::string plugin_path;

    std::string rsr_path;
    std::string log_dump_path;
    Log_Level log_level;
    bool log_stderr;
    int session_proc_threads;
    int media_proc_threads;
    int rtp_recv_threads;
    int sip_tcp_server_threads;
    int sip_udp_server_threads;
    std::string outbound_proxy;
    bool force_outbound_proxy;
    bool force_outbound_if;
    bool force_cancel_route_set;
    bool force_symmetric_rtp;
    SymmetricRtpMode symmetric_rtp_mode;
    int symmetric_rtp_delay;
    int symmetric_rtp_packets;
    bool use_raw_sockets;
    bool detect_inband_dtmf;
    bool sip_nat_handling;
    std::string next_hop;
    bool next_hop_1st_req;
    bool proxy_sticky_auth;
    bool ignore_notify_lower_cseq;
    bool ignore_sig_chld;
    bool ignore_sig_pipe;
    unsigned int session_limit;
    unsigned int session_limit_err_code;
    std::string session_limit_err_reason;
    unsigned int options_session_limit;
    unsigned int options_session_limit_err_code;
    std::string options_session_limit_err_reason;

    bool shutdown_mode;
    unsigned int shutdown_mode_err_code;
    std::string shutdown_mode_err_reason;
    bool shutdown_mode_allow_uac;
    ShutdownHandlersProcessor shutdown_handlers_processor;

    unsigned int cps_limit_err_code;
    std::string cps_limit_err_reason;
    bool enable_srtp;
    bool enable_ice;
    bool enable_rtsp;
    std::string options_transcoder_out_stats_hdr;
    std::string options_transcoder_in_stats_hdr;
    std::string transcoder_out_stats_hdr;
    std::string transcoder_in_stats_hdr;
    bool log_sessions;
    bool log_events;
    std::string sdp_origin;
    std::string sdp_session_name;
    int node_id;
    std::string node_id_prefix;
    unsigned int max_forwards;
    unsigned int max_shutdown_time;
    unsigned int dead_rtp_time;
    Dtmf::InbandDetectorType default_dtmf_detector;
    bool dtmf_offer_multirate;
    unsigned int dtmf_default_volume;
    bool single_codec_in_ok;
    std::vector<std::string> codec_order;
    std::vector<std::string> exclude_payloads;
    bool accept_forked_dialogs;
    Am100rel::State rel100;
    Log_Level unhandled_reply_log_level;
    std::string pcap_upload_queue_name;
    AmAudio::ResamplingImplementationType resampling_implementation_type;
    int dump_level;

    bool enable_zrtp;

#ifndef DISABLE_DAEMON_MODE
    bool deamon_mode;
    std::string deamon_pid_file;
    std::string deamon_uid;
    std::string deamon_gid;
#endif
};

class AmLcConfig
{
    AmLcConfig();
public:
    ~AmLcConfig();

    static AmLcConfig& instance()
    {
        static AmLcConfig config;
        return config;
    }

    std::string config_path;
    ConfigContainer m_config;

    int readConfiguration(ConfigContainer* config = &AmConfig);
    int finalizeIpConfig(ConfigContainer* config = &AmConfig);
    void dump_Ifs(ConfigContainer* config = &AmConfig);
    std::string fixIface2IP(const std::string& dev_name, bool v6_for_sip, ConfigContainer* config = &AmConfig);
    
    int setLogLevel(const std::string& level, bool apply = true);
    int setLogStderr(bool s, bool apply = true);
    int setStderrLogLevel(const std::string& level, bool apply = true);
    std::string serialize();

    int getMandatoryParameter(cfg_t* cfg, const std::string& if_name, std::string& data);
    int getMandatoryParameter(cfg_t* cfg, const std::string& if_name, int& data);
    int getMandatoryParameter(cfg_t* cfg, const std::string& if_name, unsigned int& data);
    int getMandatoryParameter(cfg_t* cfg, const std::string& if_name, unsigned short& data);
    int getMandatoryParameter(cfg_t* cfg, const std::string& if_name, bool& data);

    void applySignature(const char *signature, bool override = false);
    void addSignatureHdr(AmSipRequest &req) const;
    void addSignatureHdr(AmSipReply &reply) const;
    int addUacSignature(char *buf) const;
    int getUacSignatureLen() const;
    int addUasSignature(char *buf) const;
    int getUasSignatureLen() const;

    /**
     * helper func for fixing memory leak for cfg_raw_update (confuse.c:1069)
     * CFGF_RAW flag usage issue
     */
    static void freeRawValues(cfg_t* sec) {
        if (sec->raw_info->raw != NULL) {
            free(sec->raw_info->raw);
            sec->raw_info->raw = NULL;
            sec->raw_info->raw_len = 0;
        }
    }

protected:
    void setValidationFunction(cfg_t* cfg);
    int readSigInterfaces(cfg_t* cfg, ConfigContainer* config);
    int readMediaInterfaces(cfg_t* cfg, ConfigContainer* config);
    int readModules(cfg_t* cfg, ConfigContainer* config);
    int readGeneral(cfg_t* cfg, ConfigContainer* config);
    int readRoutings(cfg_t* cfg, ConfigContainer* config);
    int checkSipInterfaces(ConfigContainer* config);
    IP_info* readInterface(cfg_t* cfg, const std::string& if_name, AddressType ip_type);
    int readAcl(cfg_t* cfg, trsp_acl& acl, const std::string& if_name);

    bool fillSysIntfList(ConfigContainer* config);
    void fillMissingLocalSIPIPfromSysIntfs(ConfigContainer* config);
    int insertSIPInterfaceMapping(ConfigContainer* config, SIP_info& intf, int idx);
    int setNetInterface(ConfigContainer* config, IP_info& ip_if);
private:
    cfg_t* m_cfg;

    bool is_default_signature;
    std::string signature_header_uac;
    std::string signature_header_uas;
};

#endif/*AM_LC_CONFIG_H*/

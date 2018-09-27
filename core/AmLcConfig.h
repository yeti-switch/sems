#ifndef AM_LC_CONFIG_H
#define AM_LC_CONFIG_H

#include <confuse.h>
#include <map>
#include "AmLCContainers.h"
#include "AmDtmfDetector.h"
#include "Am100rel.h"
#include "AmAudio.h"
#include "AmUtils.h"

#define AmConfig_ AmLcConfig::GetInstance()

class AmLcConfig
{
    AmLcConfig();
public:
    ~AmLcConfig();

    static AmLcConfig& GetInstance()
    {
        static AmLcConfig config;
        return config;
    }
    
    std::string config_path;

    int readConfiguration();
    int finalizeIpConfig();
    void dump_Ifs();
    std::string fixIface2IP(const std::string& dev_name, bool v6_for_sip);
    
    int setLogLevel(const std::string& level, bool apply = true);
    int setLogStderr(const std::string& s, bool apply = true);
    int setStderrLogLevel(const std::string& level, bool apply = true);

    std::vector<SIP_interface> sip_ifs;
    std::vector<MEDIA_interface> media_ifs;
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
    std::string modules_path;
    std::string configs_path;
    std::string plugin_path;
    
    std::string log_dump_path;
    Log_Level log_level;
    bool log_stderr;
    int session_proc_threads;
    int media_proc_threads;
    int rtp_recv_threads;
    int sip_server_threads;
    std::string outbound_proxy;
    bool force_outbound_proxy;
    bool force_outbound_if;
    bool force_symmetric_rtp;
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
    unsigned int cps_limit_err_code;
    std::string cps_limit_err_reason;
    bool enable_rtsp;
    std::string options_transcoder_out_stats_hdr;
    std::string options_transcoder_in_stats_hdr;
    std::string transcoder_out_stats_hdr;
    std::string transcoder_in_stats_hdr;
    bool log_sessions;
    bool log_events;
    std::string signature;
    int node_id;
    std::string node_id_prefix;
    unsigned int max_forwards;
    unsigned int max_shutdown_time;
    unsigned int dead_rtp_time;
    Dtmf::InbandDetectorType default_dtmf_detector;
    bool single_codec_in_ok;
    std::vector<std::string> codec_order;
    std::vector<std::string> exclude_payloads;
    bool accept_forked_dialogs;
    Am100rel::State rel100;
    Log_Level unhandled_reply_log_level;
    std::string pcap_upload_queue_name;
    AmAudio::ResamplingImplementationType resampling_implementation_type;
    int dump_level;

#ifdef WITH_ZRTP
    bool enable_zrtp;
    bool enable_zrtp_debuglog;
#endif
#ifndef DISABLE_DAEMON_MODE
    bool deamon_mode;
    std::string deamon_pid_file;
    std::string deamon_uid;
    std::string deamon_gid;
#endif

protected:
    int readSigInterfaces();
    int readMediaInterfaces();
    int readModules();
    int readGeneral();
    int readRoutings();
    IP_info* readInterface(cfg_t* cfg, const std::string& if_name, IP_info::IP_type ip_type);
    int readAcl(cfg_t* cfg, trsp_acl& acl, const std::string& if_name);
    bool fillSysIntfList();
    int insertSIPInterfaceMapping(const std::string& ifname, const SIP_info& intf, int idx);
    int setNetInterface(IP_info& ip_if);
    void fillMissingLocalSIPIPfromSysIntfs();
    int checkSipInterfaces();
private:
    cfg_t *m_cfg;
};

#endif/*AM_LC_CONFIG_H*/

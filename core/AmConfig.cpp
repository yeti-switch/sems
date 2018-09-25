/*
 * Copyright (C) 2002-2003 Fhg Fokus
 *
 * This file is part of SEMS, a free SIP media server.
 *
 * SEMS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version. This program is released under
 * the GPL with the additional exemption that compiling, linking,
 * and/or using OpenSSL is allowed.
 *
 * For a license to use the SEMS software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * SEMS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>

#include "AmConfig.h"
#include "sems.h"
#include "log.h"
#include "AmConfigReader.h"
#include "AmUtils.h"
#include "AmSessionContainer.h"
#include "Am100rel.h"
#include "sip/transport.h"
#include "sip/resolver.h"
#include "sip/ip_util.h"
#include "sip/sip_timers.h"
#include "sip/raw_sender.h"
#include "sip/parse_via.h"

#include <cctype>
#include <algorithm>

using std::make_pair;

string       AmConfig::ConfigurationFile       = CONFIG_FILE;
string       AmConfig::ModConfigPath           = MOD_CFG_PATH;
string       AmConfig::PlugInPath              = PLUG_IN_PATH;
string       AmConfig::LoadPlugins             = "";
string       AmConfig::ExcludePlugins          = "";
string       AmConfig::ExcludePayloads         = "";
int          AmConfig::LogLevel                = L_INFO;
bool         AmConfig::LogStderr               = false;
string       AmConfig::LogDumpPath             = "/var/spool/sems/logdump";

#ifndef DISABLE_DAEMON_MODE
bool         AmConfig::DaemonMode              = DEFAULT_DAEMON_MODE;
string       AmConfig::DaemonPidFile           = DEFAULT_DAEMON_PID_FILE;
string       AmConfig::DaemonUid               = DEFAULT_DAEMON_UID;
string       AmConfig::DaemonGid               = DEFAULT_DAEMON_GID;
#endif

unsigned int AmConfig::MaxShutdownTime         = DEFAULT_MAX_SHUTDOWN_TIME;

int          AmConfig::SessionProcessorThreads = NUM_SESSION_PROCESSORS;
int          AmConfig::MediaProcessorThreads   = NUM_MEDIA_PROCESSORS;
int          AmConfig::RTPReceiverThreads      = NUM_RTP_RECEIVERS;
int          AmConfig::SIPServerThreads        = NUM_SIP_SERVERS;
string       AmConfig::OutboundProxy           = "";
bool         AmConfig::ForceOutboundProxy      = false;
string       AmConfig::NextHop                 = "";
bool         AmConfig::NextHop1stReq           = false;
bool         AmConfig::ProxyStickyAuth         = false;
bool         AmConfig::ForceOutboundIf         = false;
bool         AmConfig::ForceSymmetricRtp       = false;
bool         AmConfig::DetectInbandDtmf        = false;
bool         AmConfig::SipNATHandling          = false;
bool         AmConfig::UseRawSockets           = false;
bool         AmConfig::IgnoreNotifyLowerCSeq   = false;
bool         AmConfig::DisableDNSSRV           = false;
string       AmConfig::Signature               = "";
unsigned int AmConfig::MaxForwards             = MAX_FORWARDS;
bool	     AmConfig::SingleCodecInOK	       = false;
int          AmConfig::DumpLevel               = 0;
int          AmConfig::node_id                 = 0;
string       AmConfig::node_id_prefix          = "";
unsigned int AmConfig::DeadRtpTime             = DEAD_RTP_TIME;
bool         AmConfig::IgnoreRTPXHdrs          = false;
string       AmConfig::RegisterApplication     = "";
string       AmConfig::OptionsApplication      = "";
vector<AmConfig::app_selector> AmConfig::Applications;
bool         AmConfig::LogSessions             = false;
bool         AmConfig::LogEvents               = false;
int          AmConfig::UnhandledReplyLoglevel  = 0;
string       AmConfig::PcapUploadQueueName     = "";

bool         AmConfig::enableRTSP              = false;

#ifdef WITH_ZRTP
bool         AmConfig::enable_zrtp             = true;
bool         AmConfig::enable_zrtp_debuglog    = true;
#endif

unsigned int AmConfig::SessionLimit            = 0;
unsigned int AmConfig::SessionLimitErrCode     = 503;
string       AmConfig::SessionLimitErrReason   = "Server overload";

unsigned int AmConfig::OptionsSessionLimit            = 0;
unsigned int AmConfig::OptionsSessionLimitErrCode     = 503;
string       AmConfig::OptionsSessionLimitErrReason   = "Server overload";

unsigned int AmConfig::CPSLimitErrCode     = 503;
string       AmConfig::CPSLimitErrReason   = "Server overload";

bool         AmConfig::AcceptForkedDialogs     = true;

bool         AmConfig::ShutdownMode            = false;
bool         AmConfig::ShutdownModeAllowUAC    = false;
unsigned int AmConfig::ShutdownModeErrCode     = 503;
string       AmConfig::ShutdownModeErrReason   = "Server shutting down";
  
string AmConfig::OptionsTranscoderOutStatsHdr; // empty by default
string AmConfig::OptionsTranscoderInStatsHdr; // empty by default
string AmConfig::TranscoderOutStatsHdr; // empty by default
string AmConfig::TranscoderInStatsHdr; // empty by default

Am100rel::State AmConfig::rel100 = Am100rel::REL100_SUPPORTED;

vector <string> AmConfig::CodecOrder;

Dtmf::InbandDetectorType 
AmConfig::DefaultDTMFDetector     = Dtmf::SEMSInternal;
bool AmConfig::IgnoreSIGCHLD      = true;
bool AmConfig::IgnoreSIGPIPE      = true;

#ifdef USE_LIBSAMPLERATE
#ifndef USE_INTERNAL_RESAMPLER
AmAudio::ResamplingImplementationType AmConfig::ResamplingImplementationType = AmAudio::LIBSAMPLERATE;
#endif
#endif
#ifdef USE_INTERNAL_RESAMPLER
AmAudio::ResamplingImplementationType AmConfig::ResamplingImplementationType = AmAudio::INTERNAL_RESAMPLER;
#endif
#ifndef USE_LIBSAMPLERATE
#ifndef USE_INTERNAL_RESAMPLER
AmAudio::ResamplingImplementationType AmConfig::ResamplingImplementationType = AmAudio::UNAVAILABLE;
#endif
#endif

int AmConfig::parse_log_level(const string& level)
{
    int n;
    if (sscanf(level.c_str(), "%i", &n) == 1) {
        if (n < L_ERR || n > L_DBG) {
            fprintf(stderr,"loglevel %d not in range [%d-%d]",
                  n,L_DBG,L_ERR);
            return -1;
        }
        return n;
    }

    string s(level);
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);

    if (s == "error" || s == "err") {
        n = L_ERR;
    } else if (s == "warning" || s == "warn") {
        n = L_WARN;
    } else if (s == "info") {
        n = L_INFO;
    } else if (s=="debug" || s == "dbg") {
        n = L_DBG;
    } else {
        fprintf(stderr,"unknown loglevel value: %s",level.c_str());
        return -1;
    }
    return n;
}

int AmConfig::setLogLevel(const string& level, bool apply)
{
    int n;
    if(-1==(n = parse_log_level(level))) return 0;
    LogLevel = n;
    if (apply)
        set_log_level(LogLevel);
    return 1;
}

int AmConfig::setLogStderr(const string& s, bool apply)
{
  if ( strcasecmp(s.c_str(), "yes") == 0 ) {
    if(apply && !LogStderr)
      register_stderr_facility();
    LogStderr = true;
  } else if ( strcasecmp(s.c_str(), "no") == 0 ) {
    //deny to disable previously enabled stderr logging
  } else {
    return 0;
  }
  return 1;
}

int AmConfig::setStderrLogLevel(const string& level, bool apply)
{
    int n;
    if(-1==(n = parse_log_level(level)))
        return 0;
    if (apply && LogStderr)
        set_stderr_log_level(n);
    return 1;
}


#ifndef DISABLE_DAEMON_MODE

int AmConfig::setDaemonMode(const string& fork) {
  if ( strcasecmp(fork.c_str(), "yes") == 0 ) {
    DaemonMode = true;
  } else if ( strcasecmp(fork.c_str(), "no") == 0 ) {
    DaemonMode = false;
  } else {
    return 0;
  }
  return 1;
}		

#endif /* !DISABLE_DAEMON_MODE */

int AmConfig::setSessionProcessorThreads(const string& th) {
  if(sscanf(th.c_str(),"%u",&SessionProcessorThreads) != 1) {
    return 0;
  }
  return 1;
}

int AmConfig::setMediaProcessorThreads(const string& th) {
  if(sscanf(th.c_str(),"%u",&MediaProcessorThreads) != 1) {
    return 0;
  }
  return 1;
}

int AmConfig::setRTPReceiverThreads(const string& th) {
  if(sscanf(th.c_str(),"%u",&RTPReceiverThreads) != 1) {
    return 0;
  }
  return 1;
}

int AmConfig::setSIPServerThreads(const string& th){
  if(sscanf(th.c_str(),"%u",&SIPServerThreads) != 1) {
    return 0;
  }
  return 1;
}


int AmConfig::setDeadRtpTime(const string& drt)
{
  if(sscanf(drt.c_str(),"%u",&DeadRtpTime) != 1) {
    return 0;
  }
  return 1;
}

int AmConfig::readConfiguration()
{
  DBG("Reading configuration...\n");
  
  AmConfigReader cfg;
  int            ret=0;

  if(cfg.loadFile(AmConfig::ConfigurationFile.c_str())){
    ERROR("while loading main configuration file\n");
    return -1;
  }
       
  // take values from global configuration file
  // they will be overwritten by command line args

  // log_level
  if(cfg.hasParameter("syslog_loglevel")){
    if(!setLogLevel(cfg.getParameter("syslog_loglevel"))){
      ERROR("invalid log level specified\n");
      ret = -1;
    }
  }

  // stderr 
  if(cfg.hasParameter("stderr")){
    if(!setLogStderr(cfg.getParameter("stderr"), true)){
      ERROR("invalid stderr value specified,"
	    " valid are only yes or no\n");
      ret = -1;
    } else if(LogStderr) {
      //add stderr logging facility
      if(!setStderrLogLevel(cfg.getParameter("stderr_loglevel","2"), true)){
        ERROR("invalid stderr_loglevel value");
      }
    }
  }

#ifndef DISABLE_SYSLOG_LOG
  if (cfg.hasParameter("syslog_facility")) {
    set_syslog_facility(cfg.getParameter("syslog_facility").c_str());
  }
#endif

  // plugin_config_path
  if (cfg.hasParameter("plugin_config_path")) {
    ModConfigPath = cfg.getParameter("plugin_config_path",ModConfigPath);
  }

  if(!ModConfigPath.empty() && (ModConfigPath[ModConfigPath.length()-1] != '/'))
    ModConfigPath += '/';

  if(cfg.hasParameter("use_raw_sockets")) {
	UseRawSockets = (cfg.getParameter("use_raw_sockets") == "yes");
	if(UseRawSockets && (raw_sender::init() < 0)) {
	  UseRawSockets = false;
	}
  }

  // outbound_proxy
  if (cfg.hasParameter("outbound_proxy"))
    OutboundProxy = cfg.getParameter("outbound_proxy");

  // force_outbound_proxy
  if(cfg.hasParameter("force_outbound_proxy")) {
    ForceOutboundProxy = (cfg.getParameter("force_outbound_proxy") == "yes");
  }

  if(cfg.hasParameter("next_hop")) {
    NextHop = cfg.getParameter("next_hop");
    NextHop1stReq = (cfg.getParameter("next_hop_1st_req") == "yes");
  }

  if(cfg.hasParameter("proxy_sticky_auth")) {
    ProxyStickyAuth = (cfg.getParameter("proxy_sticky_auth") == "yes");
  }

  if(cfg.hasParameter("force_outbound_if")) {
    ForceOutboundIf = (cfg.getParameter("force_outbound_if") == "yes");
  }

  if(cfg.hasParameter("ignore_notify_lower_cseq")) {
    IgnoreNotifyLowerCSeq = (cfg.getParameter("ignore_notify_lower_cseq") == "yes");
  }

  if(cfg.hasParameter("force_symmetric_rtp")) {
    ForceSymmetricRtp = (cfg.getParameter("force_symmetric_rtp") == "yes");
  }

  DetectInbandDtmf = (cfg.getParameter("detect_inband_dtmf","no")=="yes");

  if(cfg.hasParameter("sip_nat_handling")) {
    SipNATHandling = (cfg.getParameter("sip_nat_handling") == "yes");
  }

  if(cfg.hasParameter("disable_dns_srv")) {
    _resolver::disable_srv = (cfg.getParameter("disable_dns_srv") == "yes");
  }
  

  for (int t = STIMER_A; t < __STIMER_MAX; t++) {

    string timer_cfg = string("sip_timer_") + timer_name(t);
    if(cfg.hasParameter(timer_cfg)) {

      sip_timers[t] = cfg.getParameterInt(timer_cfg, sip_timers[t]);
	  DBG("Set SIP Timer '%s' to %u ms\n", timer_name(t), sip_timers[t]);
    }
  }

  if (cfg.hasParameter("sip_timer_t2")) {
    sip_timer_t2 = cfg.getParameterInt("sip_timer_t2", DEFAULT_T2_TIMER);
	DBG("Set SIP Timer T2 to %u ms\n", sip_timer_t2);
  }

  // plugin_path
  if (cfg.hasParameter("plugin_path"))
    PlugInPath = cfg.getParameter("plugin_path");

  // load_plugins
  if (cfg.hasParameter("load_plugins"))
    LoadPlugins = cfg.getParameter("load_plugins");

  if (cfg.hasParameter("load_plugins_rtld_global")) {
    vector<string> rtld_global_plugins =
      explode(cfg.getParameter("load_plugins_rtld_global"), ",");
    for (vector<string>::iterator it=
	   rtld_global_plugins.begin(); it != rtld_global_plugins.end(); it++) {
      AmPlugIn::instance()->set_load_rtld_global(*it);
    }
  }

  if(cfg.hasParameter("log_dump_path"))
    LogDumpPath = cfg.getParameter("log_dump_path");

  // exclude_plugins
  if (cfg.hasParameter("exclude_plugins"))
    ExcludePlugins = cfg.getParameter("exclude_plugins");

  // exclude_plugins
  if (cfg.hasParameter("exclude_payloads"))
    ExcludePayloads = cfg.getParameter("exclude_payloads");

  // user_agent
  if(!cfg.hasParameter("use_default_signature")
    || (cfg.getParameter("use_default_signature")=="yes"))
    Signature = DEFAULT_SIGNATURE;
  else 
    Signature = cfg.getParameter("signature");

  if (cfg.hasParameter("max_forwards")) {
      unsigned int mf=0;
      if(str2i(cfg.getParameter("max_forwards"), mf)) {
	  ERROR("invalid max_forwards specified\n");
      }
      else {
	  MaxForwards = mf;
      }
  }

  if(cfg.hasParameter("log_sessions"))
    LogSessions = cfg.getParameter("log_sessions")=="yes";
  
  if(cfg.hasParameter("log_events"))
    LogEvents = cfg.getParameter("log_events")=="yes";

  if (cfg.hasParameter("unhandled_reply_loglevel")) {
    string msglog = cfg.getParameter("unhandled_reply_loglevel");
    if (msglog == "no") UnhandledReplyLoglevel = -1;
    else if (msglog == "error") UnhandledReplyLoglevel = 0;
    else if (msglog == "warn")  UnhandledReplyLoglevel = 1;
    else if (msglog == "info")  UnhandledReplyLoglevel = 2;
    else if (msglog == "debug") UnhandledReplyLoglevel = 3;
    else ERROR("Could not interpret unhandled_reply_loglevel \"%s\"\n",
	       msglog.c_str());
  }

  PcapUploadQueueName = cfg.getParameter("pcap_upload_queue",PcapUploadQueueName);
  enableRTSP = cfg.getParameter("rtsp_enable","no")=="yes";

  RegisterApplication  = cfg.getParameter("register_application");
  OptionsApplication  = cfg.getParameter("options_application");

  string apps_str = cfg.getParameter("application");
  auto apps = explode(apps_str,"|");
  Applications.resize(apps.size());
  int app_selector_id = 0;
  for(const auto &app_str: apps) {
    app_selector &app = Applications[app_selector_id];
    app.Application = app_str;
    if (app_str == "$(ruri.user)") {
      app.AppSelect = App_RURIUSER;
    } else if (app_str == "$(ruri.param)") {
      app.AppSelect = App_RURIPARAM;
    } else if (app_str == "$(apphdr)") {
      app.AppSelect = App_APPHDR;
    } else if (app_str == "$(mapping)") {
      app.AppSelect = App_MAPPING;
      string appcfg_fname = ModConfigPath + "app_mapping.conf";
      DBG("Loading application mapping...\n");
      if (!read_regex_mapping(appcfg_fname, "=>", "application mapping",
          app.AppMapping))
      {
        ERROR("reading application mapping\n");
        ret = -1;
      }
    } else {
      app.AppSelect = App_SPECIFIED;
    }
    app_selector_id++;
  }

  app_selector_id = 0;
  for(const auto &app_selector : AmConfig::Applications) {
    INFO("application selector %d: %s",
         app_selector_id++,app_selector.Application.c_str());
  }

#ifndef DISABLE_DAEMON_MODE

  // fork 
  if(cfg.hasParameter("fork")){
    if(!setDaemonMode(cfg.getParameter("fork"))){
      ERROR("invalid fork value specified,"
	    " valid are only yes or no\n");
      ret = -1;
    }
  }

  // daemon (alias for fork)
  if(cfg.hasParameter("daemon")){
    if(!setDaemonMode(cfg.getParameter("daemon"))){
      ERROR("invalid daemon value specified,"
	    " valid are only yes or no\n");
      ret = -1;
    }
  }

  if(cfg.hasParameter("daemon_uid")){
    DaemonUid = cfg.getParameter("daemon_uid");
  }

  if(cfg.hasParameter("daemon_gid")){
    DaemonGid = cfg.getParameter("daemon_gid");
  }

#endif /* !DISABLE_DAEMON_MODE */

  MaxShutdownTime = cfg.getParameterInt("max_shutdown_time",
					DEFAULT_MAX_SHUTDOWN_TIME);

  node_id = cfg.getParameterInt("node_id");
  if(node_id!=0) node_id_prefix = int2str(node_id) + "-";

  if(cfg.hasParameter("session_processor_threads")){
#ifdef SESSION_THREADPOOL
    if(!setSessionProcessorThreads(cfg.getParameter("session_processor_threads"))){
      ERROR("invalid session_processor_threads value specified\n");
      ret = -1;
    }
    if (SessionProcessorThreads<1) {
      ERROR("invalid session_processor_threads value specified."
	    " need at least one thread\n");
      ret = -1;
    }
#else
    WARN("session_processor_threads specified in sems.conf,\n");
    WARN("but SEMS is compiled without SESSION_THREADPOOL support.\n");
    WARN("set USE_THREADPOOL in Makefile.defs to enable session thread pool.\n");
    WARN("SEMS will start now, but every call will have its own thread.\n");    
#endif
  }

  if(cfg.hasParameter("media_processor_threads")){
    if(!setMediaProcessorThreads(cfg.getParameter("media_processor_threads"))){
      ERROR("invalid media_processor_threads value specified");
      ret = -1;
    }
  }

  if(cfg.hasParameter("rtp_receiver_threads")){
    if(!setRTPReceiverThreads(cfg.getParameter("rtp_receiver_threads"))){
      ERROR("invalid rtp_receiver_threads value specified");
      ret = -1;
    }
  }

  if(cfg.hasParameter("sip_server_threads")){
    if(!setSIPServerThreads(cfg.getParameter("sip_server_threads"))){
      ERROR("invalid sip_server_threads value specified");
      ret = -1;
    }
  }

  // single codec in 200 OK
  if(cfg.hasParameter("single_codec_in_ok")){
    SingleCodecInOK = (cfg.getParameter("single_codec_in_ok") == "yes");
  }

  // single codec in 200 OK
  if(cfg.hasParameter("ignore_rtpxheaders")){
    IgnoreRTPXHdrs = (cfg.getParameter("ignore_rtpxheaders") == "yes");
  }

  // codec_order
  CodecOrder = explode(cfg.getParameter("codec_order"), ",");

  // dead_rtp_time
  if(cfg.hasParameter("dead_rtp_time")){
    if(!setDeadRtpTime(cfg.getParameter("dead_rtp_time"))){
      ERROR("invalid dead_rtp_time value specified");
      ret = -1;
    }
  }

  if(cfg.hasParameter("dtmf_detector")){
    if (cfg.getParameter("dtmf_detector") == "spandsp") {
#ifndef USE_SPANDSP
      WARN("spandsp support not compiled in.\n");
#endif
      DefaultDTMFDetector = Dtmf::SpanDSP;
    }
  }

#ifdef WITH_ZRTP
  enable_zrtp = cfg.getParameter("enable_zrtp", "yes") == "yes";
  INFO("ZRTP %sabled\n", enable_zrtp ? "en":"dis");

  enable_zrtp_debuglog = cfg.getParameter("enable_zrtp_debuglog", "yes") == "yes";
  INFO("ZRTP debug log %sabled\n", enable_zrtp_debuglog ? "en":"dis");
#endif

  if(cfg.hasParameter("session_limit")){ 
    vector<string> limit = explode(cfg.getParameter("session_limit"), ";");
    if (limit.size() != 3) {
      ERROR("invalid session_limit specified.\n");
    } else {
      if (str2i(limit[0], SessionLimit) || str2i(limit[1], SessionLimitErrCode)) {
	ERROR("invalid session_limit specified.\n");
      }
      SessionLimitErrReason = limit[2];
    }
  }

  if(cfg.hasParameter("options_session_limit")){ 
    vector<string> limit = explode(cfg.getParameter("options_session_limit"), ";");
    if (limit.size() != 3) {
      ERROR("invalid options_session_limit specified.\n");
    } else {
      if (str2i(limit[0], OptionsSessionLimit) || str2i(limit[1], OptionsSessionLimitErrCode)) {
	ERROR("invalid options_session_limit specified.\n");
      }
      OptionsSessionLimitErrReason = limit[2];
    }
  }

  if(cfg.hasParameter("cps_limit")){ 
    unsigned int CPSLimit;
    vector<string> limit = explode(cfg.getParameter("cps_limit"), ";");
    if (limit.size() != 3) {
      ERROR("invalid cps_limit specified.\n");
    } else {
      if (str2i(limit[0], CPSLimit) || str2i(limit[1], CPSLimitErrCode)) {
	ERROR("invalid cps_limit specified.\n");
      }
      CPSLimitErrReason = limit[2];
    }
    AmSessionContainer::instance()->setCPSLimit(CPSLimit);
  }

  if(cfg.hasParameter("accept_forked_dialogs"))
    AcceptForkedDialogs = !(cfg.getParameter("accept_forked_dialogs") == "no");

  if(cfg.hasParameter("shutdown_mode_reply")){
    string c_reply = cfg.getParameter("shutdown_mode_reply");    
    size_t spos = c_reply.find(" ");
    if (spos == string::npos || spos == c_reply.length()) {
      ERROR("invalid shutdown_mode_reply specified, expected \"<code> <reason>\","
	    "e.g. shutdown_mode_reply=\"503 Not At The Moment, Please\".\n");
      ret = -1;

    } else {
      if (str2i(c_reply.substr(0, spos), ShutdownModeErrCode)) {
	ERROR("invalid shutdown_mode_reply specified, expected \"<code> <reason>\","
	      "e.g. shutdown_mode_reply=\"503 Not At The Moment, Please\".\n");
	ret = -1;
      }
      ShutdownModeErrReason = c_reply.substr(spos+1);
    }
  }

  ShutdownModeAllowUAC = (cfg.getParameter("shutdown_mode_allow_uac","no")=="yes");

  OptionsTranscoderOutStatsHdr = cfg.getParameter("options_transcoder_out_stats_hdr");
  OptionsTranscoderInStatsHdr = cfg.getParameter("options_transcoder_in_stats_hdr");
  TranscoderOutStatsHdr = cfg.getParameter("transcoder_out_stats_hdr");
  TranscoderInStatsHdr = cfg.getParameter("transcoder_in_stats_hdr");

  if (cfg.hasParameter("100rel")) {
    string rel100s = cfg.getParameter("100rel");
    if (rel100s == "disabled" || rel100s == "off") {
      rel100 = Am100rel::REL100_DISABLED;
    } else if (rel100s == "supported") {
      rel100 = Am100rel::REL100_SUPPORTED;
    } else if (rel100s == "require") {
      rel100 = Am100rel::REL100_REQUIRE;
    } else {
      ERROR("unknown setting for '100rel' config option: '%s'.\n",
	    rel100s.c_str());
      ret = -1;
    }
  }

  if (cfg.hasParameter("resampling_library")) {
	string resamplings = cfg.getParameter("resampling_library");
	if (resamplings == "libsamplerate") {
	  ResamplingImplementationType = AmAudio::LIBSAMPLERATE;
	}
  }

  return ret;
}	

#include "CoreRpc.h"
#include "AmPlugIn.h"
#include "sems.h"
#include "AmSession.h"
#include "AmEventDispatcher.h"
#include "SipCtrlInterface.h"
#include "AmSessionContainer.h"
#include "ampi/HttpClientAPI.h"
#include "sip/resolver.h"

#include "jsonArg.h"
#include "codecs_bench.h"
#include "AmB2BSession.h"
#include "AmAudioFileRecorder.h"

#include "signal.h"
#include <fstream>

static const bool RPC_CMD_SUCC = true;

static int check_dir_write_permissions(const string &dir)
{
    std::ofstream st;
    string testfile = dir + "/test";
    st.open(testfile.c_str(),std::ofstream::out | std::ofstream::trunc);
    if(!st.is_open()){
        ERROR("can't write test file in '%s' directory",dir.c_str());
        return 1;
    }
    st.close();
    std::remove(testfile.c_str());
    return 0;
}

static void addLoggingFacilityLogLevel(AmArg& ret,const string &facility_name)
{
    AmLoggingFacility* fac = AmPlugIn::instance()->getFactory4LogFaclty(facility_name);
    if(0==fac)
        return;
    ret[fac->getName()] = fac->getLogLevel();
}

static void setLoggingFacilityLogLevel(const AmArg& args, AmArg& ret,const string &facility_name)
{
    int log_level;
    if(!args.size()){
        throw AmSession::Exception(500,"missed new log_level");
    }
    args.assertArrayFmt("s");
    if(!str2int(args.get(0).asCStr(),log_level)){
        throw AmSession::Exception(500,"invalid log_level fmt");
    }

    AmLoggingFacility* fac = AmPlugIn::instance()->getFactory4LogFaclty(facility_name);
    if(0==fac){
        throw AmSession::Exception(404,"logging facility not loaded");
    }

    fac->setLogLevel(log_level);

    ret = RPC_CMD_SUCC;
}

static void setDumpLevel(int dump_level){
    INFO("change system dump_level from %s to %s",
        dump_level2str(AmConfig::DumpLevel),
        dump_level2str(dump_level));
    AmConfig::DumpLevel = dump_level;
}

static const char *dump_level_names[] = {
    "none",
    "signalling",   //LOG_SIP_MASK
    "rtp",          //LOG_RTP_MASK
    "full"          //LOG_FULL_MASK
};
static const int dump_level_names_count =
    (sizeof(dump_level_names)/sizeof(dump_level_names[0]))-1;
const char *dump_level2str(int dump_level){
    if(dump_level < 0 || dump_level > dump_level_names_count){
        return "invalid";
    }
    return dump_level_names[dump_level];
}


static void AmSession2AmArg(AmSession *leg, AmArg &s)
{
    AmB2BSession *b2b_leg = dynamic_cast<AmB2BSession *>(leg);
    if(b2b_leg) {
        s["a_leg"] = b2b_leg->getALeg();
        s["call_group"] = b2b_leg->getCallgroup();
        s["session_status"] = b2b_leg->getProcessingStatusStr();
        s["other_id"] = b2b_leg->getOtherId();
    }

    AmSipDialog *dlg = leg->dlg;
    if(dlg){
        s["dlg_status"] = dlg->getStatusStr();
        s["dlg_callid"] = dlg->getCallid();
        s["dlg_ruri"] = dlg->getRemoteUri();
    }
}

static void dump_session_info(
    const AmEventDispatcher::QueueEntry &entry,
    void *arg)
{
    AmArg &a = *(AmArg *)arg;
    a.assertStruct();
    AmSession *leg = dynamic_cast<AmSession *>(entry.q);
    if(!leg) return;
    AmSession2AmArg(leg,a);
}

static void dump_sessions_info(
    const string &key,
    const AmEventDispatcher::QueueEntry &entry,
    void *arg)
{
    AmSession *leg = dynamic_cast<AmSession *>(entry.q);
    if(!leg) return;
    AmArg &ret = *(AmArg *)arg;
    AmSession2AmArg(leg,ret[key]);
}

static void set_system_shutdown(bool shutdown)
{
    AmConfig::ShutdownMode = shutdown;
    INFO("ShutDownMode changed to %d",AmConfig::ShutdownMode);

    if(AmConfig::ShutdownMode&&!AmSession::getSessionNum()){
        //commit suicide immediatly
        INFO("no active session on graceful shutdown command. exit immediatly");
        kill(getpid(),SIGINT);
    }
}

CoreRpc::~CoreRpc()
{ }

void CoreRpc::init_rpc_tree()
{
    //show
    AmArg &show = reg_leaf(root,"show");
        reg_method(show,"status","",&CoreRpc::showStatus);
        reg_method(show,"connections","",&CoreRpc::showConnections);
        reg_method(show,"version","show version",&CoreRpc::showVersion);
        reg_method(show,"interfaces","active media streams info",&CoreRpc::showInterfaces);
        reg_method(show,"payloads","",&CoreRpc::showPayloads);
        reg_method(show,"log-level","",&CoreRpc::showLogLevel);
        reg_method(show,"dump-level","",&CoreRpc::showDumpLevel);
        AmArg &show_sessions = reg_method_arg(show,"sessions","show runtime sessions",&CoreRpc::showSessionsInfo,
                                              "active sessions","<LOCAL-TAG>","show sessions related to given local_tag");
            reg_method(show_sessions,"count","",&CoreRpc::showSessionsCount);
            reg_method(show_sessions,"limit","",&CoreRpc::showSessionsLimit);
        AmArg &show_media = reg_leaf(show,"media","media processor instance");
            reg_method(show_media,"streams","active media streams info",&CoreRpc::showMediaStreams);
        AmArg &show_recorder = reg_leaf(show,"recorder","async audio recorder instance");
            reg_method(show_recorder,"stats","",&CoreRpc::showRecorderStats);
        AmArg &show_http = reg_leaf(show,"http","http client instance");
            reg_method(show_http,"destinations","",&CoreRpc::showHttpDestinations);
            reg_method(show_http,"stats","",&CoreRpc::showHttpStats);

    //request
    AmArg &request = reg_leaf(root,"request");
        AmArg &request_log = reg_leaf(request,"log");
            reg_method(request_log,"dump","",&CoreRpc::requestLogDump);
        AmArg &request_shutdown = reg_leaf(request,"shutdown");
            reg_method(request_shutdown,"normal","",&CoreRpc::requestShutdownNormal);
            reg_method(request_shutdown,"immediate","",&CoreRpc::requestShutdownImmediate);
            reg_method(request_shutdown,"graceful","",&CoreRpc::requestShutdownGraceful);
            reg_method(request_shutdown,"cancel","",&CoreRpc::requestShutdownCancel);
        AmArg &request_resolver = reg_leaf(request,"resolver");
            reg_method(request_resolver,"clear","",&CoreRpc::requestResolverClear);
            reg_method(request_resolver,"get","",&CoreRpc::requestResolverGet);
        AmArg &request_http = reg_leaf(request,"http","http_client instance");
        reg_method(request_http,"upload","manual event generation",&CoreRpc::requestHttpUpload);

    //set
    AmArg &set = reg_leaf(root,"set");
        AmArg &set_loglevel = reg_leaf(set,"log-level");
            reg_method(set_loglevel,"syslog","<log_level>",&CoreRpc::setLogSyslogLevel);
            reg_method(set_loglevel,"di_log","<log_level>",&CoreRpc::setLogDiLogLevel);

        AmArg &set_dumplevel = reg_leaf(set,"dump-level");
            reg_method(set_dumplevel,"none","",&CoreRpc::setDumpLevelNone);
            reg_method(set_dumplevel,"signalling","",&CoreRpc::setDumpLevelSignalling);
            reg_method(set_dumplevel,"rtp","",&CoreRpc::setDumpLevelRtp);
            reg_method(set_dumplevel,"full","",&CoreRpc::setDumpLevelFull);

        AmArg &set_sessions = reg_leaf(set,"sessions");
            reg_method(set_sessions,"limit","",&CoreRpc::setSessionsLimit);
}

void CoreRpc::log_invoke(const string& method, const AmArg& args) const
{
    DBG("CoreRpc::log_invoke(%s,%s)",method.c_str(),AmArg::print(args).c_str());
}

int CoreRpc::onLoad()
{
    _inc_ref();

    if(!AmConfig::LogDumpPath.empty()
       && check_dir_write_permissions(AmConfig::LogDumpPath))
    {
        return -1;
    }

    start_time = time(NULL);
    timerclear(&last_shutdown_time);

    init_rpc();
    AmPlugIn::registerDIInterface("core",this);

    return 0;
}

void CoreRpc::invoke(const string& method, const AmArg& args, AmArg& ret)
{
    if(method=="_list") {
        AmArg plugin_cmd;
        plugin_cmd.push("plugin");
        plugin_cmd.push("");
        ret.push(plugin_cmd);
        RpcTreeHandler::invoke(method,args,ret);
        return;
    }

    if(method=="plugin") {
        plugin(args,ret);
        return;
    }

    RpcTreeHandler::invoke(method,args,ret);
}

void CoreRpc::showVersion(const AmArg& args, AmArg& ret)
{
    ret["core_build"] = get_sems_version();
}

void CoreRpc::showMediaStreams(const AmArg& args, AmArg& ret)
{
    AmMediaProcessor::instance()->getInfo(ret);
}

void CoreRpc::showInterfaces(const AmArg& args, AmArg& ret)
{
    AmArg &sig = ret["sip"];
    for(int i=0; i<(int)AmConfig::SIP_Ifs.size(); i++) {
        AmConfig::SIP_interface& iface = AmConfig::SIP_Ifs[i];
        AmArg am_iface;
        am_iface["idx"] = i;
        am_iface["media_if_idx"] = iface.RtpInterface;
        am_iface["sys_name"] = iface.NetIf;
        am_iface["sys_idx"] = (int)iface.NetIfIdx;
        am_iface["local_ip"] = iface.LocalIP;
        am_iface["udp_local_port"] = (int)iface.udp_local_port;
        am_iface["tcp_local_port"] = (int)iface.tcp_local_port;
        am_iface["public_ip"] = iface.PublicIP;
        am_iface["static_client_port"] = (iface.SigSockOpts&trsp_socket::static_client_port)!= 0;
        am_iface["use_raw_sockets"] = (iface.SigSockOpts&trsp_socket::use_raw_sockets)!= 0;
        am_iface["force_via_address"] = (iface.SigSockOpts&trsp_socket::force_via_address) != 0;
        am_iface["force_outbound_if"] = (iface.SigSockOpts&trsp_socket::force_outbound_if) != 0;
        am_iface["dscp"] = iface.dscp;
        am_iface["tos_byte"] = iface.tos_byte;
        sig[iface.name] = am_iface;
    }

    AmArg &rtp = ret["media"];
    for(int i=0; i<(int)AmConfig::RTP_Ifs.size(); i++) {
        AmConfig::RTP_interface& iface = AmConfig::RTP_Ifs[i];
        AmArg am_iface;
        am_iface["idx"] = i;
        am_iface["sys_name"] = iface.NetIf;
        am_iface["sys_idx"] = (int)iface.NetIfIdx;
        am_iface["local_ip"] = iface.LocalIP;
        am_iface["public_ip"] = iface.PublicIP;
        am_iface["rtp_low_port"] = iface.RtpLowPort;
        am_iface["rtp_high_port"] = iface.RtpHighPort;
        am_iface["use_raw_sockets"] = (iface.MediaSockOpts&trsp_socket::use_raw_sockets)!= 0;
        am_iface["dscp"] = iface.dscp;
        am_iface["tos_byte"] = iface.tos_byte;
        string name = iface.name.empty() ? "default" : iface.name;
        rtp[name] = am_iface;
    }

    AmArg &sip_map = ret["sip_ip_map"];
    for(multimap<string,unsigned short>::iterator it = AmConfig::LocalSIPIP2If.begin();
        it != AmConfig::LocalSIPIP2If.end(); ++it) {
        AmConfig::SIP_interface& iface = AmConfig::SIP_Ifs[it->second];
        sip_map[it->first] = iface.name.empty() ? "default" : iface.name;
    }

    AmArg &sip_names_map = ret["sip_names_map"];
    for(const auto &m: AmConfig::SIP_If_names)
        sip_names_map[m.first] = m.second;

    AmArg &media_names_map = ret["media_names_map"];
    for(const auto &m: AmConfig::RTP_If_names)
        media_names_map[m.first] = m.second;
}

void CoreRpc::showPayloads(const AmArg& args, AmArg& ret)
{
    vector<SdpPayload> payloads;
    unsigned char *buf;
    int size = 0;

    //bool compute_cost = args.size() && args[0] == "benchmark";
    bool compute_cost = false;
    string path = args.size()>1 ? args[1].asCStr() : DEFAULT_BENCH_FILE_PATH;

    const AmPlugIn* plugin = AmPlugIn::instance();
    plugin->getPayloads(payloads);

    if(compute_cost){
        size = load_testing_source(path,buf);
        compute_cost = size > 0;
    }

    vector<SdpPayload>::const_iterator it = payloads.begin();
    for(;it!=payloads.end();++it){
        const SdpPayload &p = *it;
        ret.push(p.encoding_name,AmArg());
        AmArg &a = ret[p.encoding_name];

        DBG("process codec: %s (%d)",
            p.encoding_name.c_str(),p.payload_type);
        a["payload_type"] = p.payload_type;
        a["clock_rate"] = p.clock_rate;
        if(compute_cost){
            get_codec_cost(p.payload_type,buf,size,a);
        }
    }

    if(compute_cost)
        delete[] buf;
}

void CoreRpc::showLogLevel(const AmArg& args, AmArg& ret)
{
    ret["log_level"] = log_level;
    addLoggingFacilityLogLevel(ret["facilities"],"syslog");
    addLoggingFacilityLogLevel(ret["facilities"],"di_log");
}

void CoreRpc::setLogSyslogLevel(const AmArg& args, AmArg& ret)
{
    setLoggingFacilityLogLevel(args,ret,"syslog");
}

void CoreRpc::setLogDiLogLevel(const AmArg& args, AmArg& ret)
{
    setLoggingFacilityLogLevel(args,ret,"di_log");
}

void CoreRpc::showDumpLevel(const AmArg&, AmArg& ret)
{
    ret = dump_level2str(AmConfig::DumpLevel);
}

void CoreRpc::setDumpLevelNone(const AmArg&, AmArg& ret)
{
    setDumpLevel(LOG_NONE_MASK);
    ret = RPC_CMD_SUCC;
}

void CoreRpc::setDumpLevelSignalling(const AmArg&, AmArg& ret)
{
    setDumpLevel(LOG_SIP_MASK);
    ret = RPC_CMD_SUCC;
}

void CoreRpc::setDumpLevelRtp(const AmArg&, AmArg& ret)
{
    setDumpLevel(LOG_RTP_MASK);
    ret = RPC_CMD_SUCC;
}

void CoreRpc::setDumpLevelFull(const AmArg&, AmArg& ret)
{
    setDumpLevel(LOG_FULL_MASK);
    ret = RPC_CMD_SUCC;
}

void CoreRpc::showStatus(const AmArg&, AmArg& ret)
{
    ret["shutdown_mode"] = (bool)AmConfig::ShutdownMode;
    ret["shutdown_request_time"] = !timerisset(&last_shutdown_time) ?
        "nil" : timeval2str(last_shutdown_time);
    ret["core_version"] = SEMS_VERSION;
    ret["sessions"] = (int)AmSession::getSessionNum();
    ret["dump_level"] = dump_level2str(AmConfig::DumpLevel);

    time_t now = time(NULL);
    ret["localtime"] = now;
    ret["uptime"] = difftime(now,start_time);
}

void CoreRpc::showConnections(const AmArg&, AmArg& ret)
{
    SipCtrlInterface::instance()->getInfo(ret);
}

void CoreRpc::showSessionsInfo(const AmArg& args, AmArg& ret)
{
    ret.assertStruct();
    if(!args.size()){
        AmEventDispatcher::instance()->iterate(&dump_sessions_info,&ret);
    } else {
        const string local_tag = args[0].asCStr();
        AmArg &session_info = ret[local_tag];
        AmEventDispatcher::instance()->apply(
            local_tag,
            &dump_session_info,
            &session_info);
        if(isArgStruct(session_info) &&
            session_info.hasMember("other_id"))
        {
            const string other_local_tag = session_info["other_id"].asCStr();
            AmArg &other_session_info = ret[other_local_tag];
            AmEventDispatcher::instance()->apply(
                other_local_tag,
                &dump_session_info,
                &other_session_info);
        }
    }
}

void CoreRpc::showSessionsCount(const AmArg&, AmArg& ret)
{
    ret = (int)AmSession::getSessionNum();
}

void CoreRpc::showSessionsLimit(const AmArg&, AmArg& ret)
{
    ret["limit"] = (long int)AmConfig::SessionLimit;
    ret["limit_error_code"] = (long int)AmConfig::SessionLimitErrCode;
    ret["limit_error_reason"] = AmConfig::SessionLimitErrReason;
}

void CoreRpc::setSessionsLimit(const AmArg& args, AmArg& ret)
{
    if(args.size()<3) {
        throw AmSession::Exception(500,"missed parameter");
    }
    args.assertArrayFmt("sss");

    int limit,code;
    if(!str2int(args.get(0).asCStr(),limit)){
        throw AmSession::Exception(500,"non integer value for sessions limit");
    }
    if(!str2int(args.get(1).asCStr(),code)){
        throw AmSession::Exception(500,"non integer value for overload response code");
    }

    AmConfig::SessionLimit = limit;
    AmConfig::SessionLimitErrCode = code;
    AmConfig::SessionLimitErrReason = args.get(2).asCStr();

    ret = RPC_CMD_SUCC;
}

void CoreRpc::requestShutdownNormal(const AmArg& args, AmArg& ret)
{
    kill(getpid(),SIGINT);
    ret = RPC_CMD_SUCC;
}

void CoreRpc::requestShutdownImmediate(const AmArg& args, AmArg& ret)
{
    kill(getpid(),SIGTERM);
    ret = RPC_CMD_SUCC;
}

void CoreRpc::requestShutdownGraceful(const AmArg& args, AmArg& ret)
{
    gettimeofday(&last_shutdown_time,NULL);
    set_system_shutdown(true);
    ret = RPC_CMD_SUCC;
}

void CoreRpc::requestShutdownCancel(const AmArg& args, AmArg& ret)
{
    timerclear(&last_shutdown_time);
    set_system_shutdown(false);
    ret = RPC_CMD_SUCC;
}

void CoreRpc::showRecorderStats(const AmArg&, AmArg& ret)
{
    AmAudioFileRecorderProcessor::instance()->getStats(ret);
}

void CoreRpc::showHttpDestinations(const AmArg& args, AmArg& ret)
{
    AmDynInvokeFactory* f = AmPlugIn::instance()->getFactory4Di("http_client");
    if(NULL==f){
        throw AmSession::Exception(500,"http_client module not loaded");
    }
    AmDynInvoke* i = f->getInstance();
    if(NULL==i){
        throw AmSession::Exception(500,"can't get http client instance");
    }
    i->invoke("show",args,ret);
}

void CoreRpc::showHttpStats(const AmArg& args, AmArg& ret)
{
    AmDynInvokeFactory* f = AmPlugIn::instance()->getFactory4Di("http_client");
    if(NULL==f){
        throw AmSession::Exception(500,"http_client module not loaded");
    }
    AmDynInvoke* i = f->getInstance();
    if(NULL==i){
        throw AmSession::Exception(500,"can't get http client instance");
    }
    i->invoke("stats",args,ret);
}

void CoreRpc::requestHttpUpload(const AmArg& args, AmArg& ret)
{
    args.assertArrayFmt("sss");

    if (AmSessionContainer::instance()->postEvent(
        HTTP_EVENT_QUEUE,
        new HttpUploadEvent(args.get(0).asCStr(),
                            args.get(1).asCStr(),
                            args.get(2).asCStr(),
                            string())))
    {
        ret = "posted to queue";
    } else {
        ret = "failed to post event";
    }
}

void CoreRpc::requestResolverClear(const AmArg&, AmArg& ret)
{
    resolver::instance()->clear_cache();
    ret = RPC_CMD_SUCC;
}


void CoreRpc::requestResolverGet(const AmArg& args, AmArg& ret)
{
    if(!args.size()){
        throw AmSession::Exception(500,"missed parameter");
    }
    string target = args[0].asCStr();
    if(target.empty()) return;

    dns_handle h;
    sockaddr_storage remote_ip;

    bzero(&remote_ip,sizeof(remote_ip));
    if(-1==resolver::instance()->resolve_name(
        target.c_str(),
        &h,&remote_ip,
        IPv4,
        target[0]=='_' ? dns_r_srv : dns_r_a))
    {
        throw AmSession::Exception(500,"unresolvable destination");
    }
    ret["address"] = get_addr_str_sip(&remote_ip).c_str();
    unsigned short port = am_get_port(&remote_ip);
    ret["port"] = port ? port : 5060;
    h.dump(ret["handler"]);
}

void CoreRpc::requestLogDump(const AmArg& args, AmArg& ret)
{
    if(AmConfig::LogDumpPath.empty())
        throw AmSession::Exception(500,"log_dump_path is not set");

    AmDynInvokeFactory* di_log = AmPlugIn::instance()->getFactory4Di("di_log");
    if(0==di_log)
        throw AmSession::Exception(404,"di_log module not loaded");

    struct timeval t;
    gettimeofday(&t,NULL);

    string path = AmConfig::LogDumpPath + "/";
    path += int2str((unsigned int)t.tv_sec) + "-";
    path += int2hex(get_random());
    path += int2hex(t.tv_sec) + int2hex(t.tv_usec);
    path += int2hex((unsigned int)((unsigned long)pthread_self()));

    AmArg di_log_args;
    di_log_args.push(path);

    di_log->getInstance()->invoke("dumplogtodisk",di_log_args,ret);
}

void CoreRpc::plugin(const AmArg& args, AmArg& ret)
{
    static const string self_factory("core");

    if(!args.size())
        return;

    AmArg params = args;
    AmArg method_arg;
    params.pop(method_arg);
    const string &method = method_arg.asCStr();

    if(method=="_list") {
        AmArg factories_list;
        AmPlugIn::instance()->listFactories4Di(factories_list);
        for(size_t i = 0; i < factories_list.size(); i++)
            if(self_factory!=factories_list.get(i).asCStr()) {
                ret.push(AmArg());
                ret.back().push(factories_list.get(i));
                ret.back().push("");
            }
        return;
    }

    if(method==self_factory)
        throw AmSession::Exception(500,"calling 'core' using factory proxy method leads to the loop");

    if(!params.size())
        throw AmSession::Exception(500,"missed method for factory");

    AmDynInvokeFactory* fact = AmPlugIn::instance()->getFactory4Di(method);
    if (fact==NULL)
        throw AmSession::Exception(404,"module not loaded");
    AmDynInvoke* di_inst = fact->getInstance();
    if(!di_inst)
        throw AmSession::Exception(500,"failed to instanciate module");

    AmArg fact_meth;
    params.pop(fact_meth);
    di_inst->invoke(fact_meth.asCStr(), params, ret);
}


#pragma once

#include "AmApi.h"
#include "RpcTreeHandler.h"

#define LOG_NONE_MASK   0x0
#define LOG_SIP_MASK    0x1
#define LOG_RTP_MASK    0x2
#define LOG_FULL_MASK   (LOG_SIP_MASK|LOG_RTP_MASK)

const char *dump_level2str(int dump_level);

class CoreRpc final
  : public RpcTreeHandler<CoreRpc>,
    public AmDynInvokeFactory
{
    time_t start_time;
    static timeval last_shutdown_time;

    CoreRpc()
      : RpcTreeHandler<CoreRpc>(true),
        AmDynInvokeFactory("core")
    { }

  protected:

    void init_rpc_tree();
    void log_invoke(const string& method, const AmArg& args) const;

  public:
    static CoreRpc& instance();

    AmDynInvoke* getInstance() { return this; }
    int onLoad();
    static void set_system_shutdown(bool shutdown);

    CoreRpc(CoreRpc const&) = delete;
    void operator=(CoreRpc const&) = delete;
    ~CoreRpc();

    //make some of the handlers public for back-compatibility
    rpc_handler showVersion;
    rpc_handler showConfig;
    rpc_handler showMediaStreams;
    rpc_handler showInterfaces;

    rpc_handler showPayloads;
    rpc_handler showLogLevel;
    rpc_handler setLogSyslogLevel;
    rpc_handler setLogDiLogLevel;
    rpc_handler setLogStderrLogLevel;
    rpc_handler stopSslKeyLog;
    rpc_handler restartSslKeyLog;

    rpc_handler showDumpLevel;
    rpc_handler setDumpLevelNone;
    rpc_handler setDumpLevelSignalling;
    rpc_handler setDumpLevelRtp;
    rpc_handler setDumpLevelFull;

    rpc_handler showModules;
    rpc_handler showStatus;
    rpc_handler showShutdownStatus;
    rpc_handler showConnections;
    rpc_handler showTrBlacklist;
    rpc_handler showTrCount;
    rpc_handler showTrList;
    rpc_handler showUsedPorts;
    rpc_handler showSessionsInfo;
    rpc_handler showSessionsCount;
    rpc_handler showSessionsLimit;
    rpc_handler setSessionsLimit;
    rpc_handler showResolverCount;
    rpc_handler showResolverCache;

    rpc_handler requestShutdownNormal;
    rpc_handler requestShutdownImmediate;
    rpc_handler requestShutdownGraceful;
    rpc_handler requestShutdownGracefulNoAutoTerm;
    rpc_handler requestShutdownCancel;
    rpc_handler requestReloadCertificate;
    rpc_handler setShutdownAutoTerm;

    rpc_handler showRecorderStats;

    rpc_handler requestResolverClear;
    rpc_handler requestResolverGet;

    rpc_handler requestLogDump;

    rpc_handler plugin;

};


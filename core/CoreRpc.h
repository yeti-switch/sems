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
    timeval last_shutdown_time;

    CoreRpc()
      : AmDynInvokeFactory("core")
    { }

  protected:

    void init_rpc_tree();
    void log_invoke(const string& method, const AmArg& args) const;

  public:
    AmDynInvoke* getInstance() { return this; }
    int onLoad();
    static CoreRpc& instance()
    {
        static CoreRpc _instance;
        return _instance;
    }

    CoreRpc(CoreRpc const&) = delete;
    void operator=(CoreRpc const&) = delete;
    ~CoreRpc();

    void invoke(const string& method, const AmArg& args, AmArg& ret);

    //make some of the handlers public for back-compatibility
    rpc_handler showVersion;
    rpc_handler showMediaStreams;
    rpc_handler showInterfaces;

    rpc_handler showPayloads;
    rpc_handler showLogLevel;
    rpc_handler setLogSyslogLevel;
    rpc_handler setLogDiLogLevel;

    rpc_handler showDumpLevel;
    rpc_handler setDumpLevelNone;
    rpc_handler setDumpLevelSignalling;
    rpc_handler setDumpLevelRtp;
    rpc_handler setDumpLevelFull;

    rpc_handler showStatus;
    rpc_handler showSessionsInfo;
    rpc_handler showSessionsCount;
    rpc_handler showSessionsLimit;
    rpc_handler setSessionsLimit;

    rpc_handler requestShutdownNormal;
    rpc_handler requestShutdownImmediate;
    rpc_handler requestShutdownGraceful;
    rpc_handler requestShutdownCancel;

    rpc_handler showRecorderStats;

    rpc_handler showHttpDestinations;
    rpc_handler showHttpStats;
    rpc_handler requestHttpUpload;

    rpc_handler requestResolverClear;
    rpc_handler requestResolverGet;

    rpc_handler requestLogDump;

    rpc_handler plugin;

};


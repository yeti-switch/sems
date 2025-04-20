#include <stdint.h>
#include "Config.h"
#include "WorkersManager.h"
#include <gtest/gtest.h>
#include <botan/internal/locking_allocator.h>
#include "AmApi.h"
#include "AmLcConfig.h"
#include "AmSessionProcessor.h"
#include "AmEventDispatcher.h"
#include "CoreRpc.h"
#include "ObjectsCounter.h"

class TesterLogFac : public AmLoggingFacility {
    static TesterLogFac *_instance;
    TesterLogFac()
        : AmLoggingFacility("stderr","", L_WARN)
    { }
  public:
    static TesterLogFac &instance() {
        if(!_instance) _instance = new TesterLogFac();
        return *_instance;
    }
    ~TesterLogFac() {}
    int onLoad() {  return 0; }
    void log(int level_, pid_t pid, pid_t tid,
             const char* func, const char* file, int line,
             const char* msg_, int msg_len_)
    {
        fprintf(stderr, COMPLETE_LOG_FMT);
        fflush(stderr);
    }
    static void dispose() {
        if(_instance) {
            delete _instance;
            _instance = NULL;
        }
    }
};
TesterLogFac *TesterLogFac::_instance = NULL;

static string config_path = "./unit_tests/etc/sems_test.cfg";

void GetConfigPath(int argc, char** argv) {
    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "-c") == 0) {
            i++;
            config_path = argv[i];
            return;
        }
    }
}

int ParseCommandLine(int argc, char** argv)
{
    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "-c") == 0) { i++; continue; }
        int ret = test_config::instance()->parseCmdOverride(argv[i]);
        if(ret < 0) return -1;
        else if(ret > 0) {}
    }

    return 0;
}

#include <event.h>

int main(int argc, char** argv)
{
    init_core_objects_counters();

    TesterLogFac& testlog = TesterLogFac::instance();
	register_log_hook(&testlog);
    AmPlugIn::registerLoggingFacility(testlog.getName(), &testlog);

    //instantiation to ensure mlock_allocator will be destroyed after the AmLcConfig
    Botan::mlock_allocator::instance();

    GetConfigPath(argc, argv);
    if (test_config::instance()->readConfiguration(config_path) < 0 ||
        ParseCommandLine(argc, argv) < 0 ||
        AmLcConfig::instance().readConfiguration() < 0 ||
        AmLcConfig::instance().finalizeIpConfig() < 0) return -1;

    if(AmConfig.sip_if_names.find(test_config::instance()->signalling_interface) == AmConfig.sip_if_names.end()) {
        ERROR("interface name %s absent in sems config", test_config::instance()->signalling_interface.c_str());
        return -1;
    }

    worker_manager::instance()->init();
    AmPlugIn::instance()->init();
    if(AmPlugIn::instance()->load(AmConfig.modules_path, test_config::instance()->allow_plugins))
        return -1;

    if(AmPlugIn::instance()->initLoggingPlugins())
      return -1;

    AmPlugIn::instance()->registerLoggingPlugins();

    if(AmPlugIn::instance()->initPlugins())
      return -1;

    AmSessionProcessor::addThreads(AmConfig.session_proc_threads);

    if(CoreRpc::instance().onLoad()) {
      ERROR("failed to initialize CoreRpc");
      return -1;
    }

	TesterLogFac::instance().setLogLevel(test_config::instance()->log_level);

    restart_ssl_key_logger("");
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();

	TesterLogFac::instance().setLogLevel(L_WARN);

    worker_manager::instance()->dispose();

    AmSessionProcessor::stop();

    resolver::instance()->clear_cache();
    resolver::dispose();
    AmPlugIn::dispose();
    AmEventDispatcher::dispose();
    AmSessionContainer::dispose();
    statistics::dispose();
    test_config::dispose();
    TesterLogFac::dispose();
    dispose_syslog_fac();
    return ret;
}

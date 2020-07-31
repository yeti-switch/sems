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

#include "sems.h"
#include "AmUtils.h"
#include "AmPlugIn.h"
#include "AmSessionContainer.h"
#include "AmMediaProcessor.h"
#include "AmStunProcessor.h"
#include "AmRtpReceiver.h"
#include "AmEventDispatcher.h"
#include "AmSessionProcessor.h"
#include "AmAudioFileRecorder.h"
#include "AmAppTimer.h"
#include "RtspClient.h"
#include "CoreRpc.h"
#include "AmSrtpConnection.h"
//#include "sip/async_file_writer.h"

#include "SipCtrlInterface.h"
#include "sip/trans_table.h"

#include "log.h"

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>

#include <grp.h>
#include <pwd.h>

#include <event2/thread.h>

//#include <sys/wait.h>
//#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef PROPAGATE_COREDUMP_SETTINGS
#include <sys/resource.h>
#include <sys/prctl.h>
#endif

#include <string>
using std::string;

#if defined(__linux__)
#include <sys/prctl.h>
#include <srtp.h>
#include "PcapFileRecorder.h"
#include "sip/tls_trsp.h"
#include "sip/tr_blacklist.h"
#include "AmStatistics.h"
#include <getopt.h>
#endif

const char* progname = NULL;    /**< Program name (actually argv[0])*/
int main_pid = 0;               /**< Main process PID */
time_t start_time;

/** SIP stack (controller interface) */
#define sip_ctrl (*SipCtrlInterface::instance())


const char *get_sems_version(void)
{
    return SEMS_VERSION;
}

static void print_supported_srtp_profiles() {
    printf(
        "  Supported SRTP profiles:\n"
    );
    for(int i = 1; i <= CP_MAX; i++) {
        string data = SdpCrypto::profile2str((CryptoProfile)i);
        if(SdpCrypto::str2profile(data) != CP_NONE)
            printf("    %s\n", data.c_str());
    }
    printf(
        "\n"
        "  Related sems.conf options:\n"
        "    media-interfaces.interface.ip4.rtp.srtp.sdes.profiles\n"
        "    media-interfaces.interface.ip6.rtp.srtp.sdes.profiles\n"
        "\n"
        "    media-interfaces.interface.ip4.rtp.srtp.dtls.client.profiles\n"
        "    media-interfaces.interface.ip6.rtp.srtp.dtls.client.profiles\n"
        "\n"
    );
}

static void print_supported_zrtp_attributes() {

    printf(
        "  Supported ZRTP attributes:\n"
        "    hash algorithms:\n"
        "       S256, S384, N256, N384\n"
        "    ciphers algorithms:\n"
        "       AES1, AES2, AES3, 2FS1, 2FS2, 2FS3\n"
        "    authtag algorithms:\n"
        "       HS32, HS80, SK32, SK64\n"
        "    dhmode algorithms:\n"
        "       DH2K, EC25, DH3K, EC38, EC52, PRSH, MULT\n"
        "    sas algorithms:\n"
        "       B32, B256\n"
    );
}

static void print_usage(bool short_=false)
{
  if (short_) {
    printf("Usage: %s [OPTIONS]\n"
           "Try `%s -h' for more information.\n",
           progname, progname);
  }
  else {
    printf(
        "Usage: %s [STARTUP_OPTIONS...|INFORMATIONAL_OPTION]\n\n"
        " Startup options:\n"
        "    -f <file>            set configuration file (default: " CONFIG_FILE ")\n"
        "    -x <dir>             set path for plug-ins\n"
#ifndef DISABLE_DAEMON_MODE
        "\n"
        "    -P <file>            set PID file (default: " DEFAULT_DAEMON_PID_FILE ")\n"
        "    -u <uid>             set user ID\n"
        "    -g <gid>             set group ID\n"
#endif
        "\n"
        "    -D <level>           set stderr log level (default: %d):\n"
        "                         0 - error, 1 - warning, 2 - info, 3 - debug\n\n"
        "    -E                   enable debug mode (do not daemonize, log to stderr).\n"
        "\n"
        " Informational options:\n"
        "    --list-srtp-profiles print supported SRTP profiles\n"
        "    --list-zrtp-attributes print supported ZRTP attributes\n"
        "\n"
        "    -v, --version        print version\n"
        "    -h, --help           print this help\n"
        "\n",
        progname, AmConfig.log_level
    );
  }
}

/* Note: The function should not use log because it is called before logging is initialized. */
static bool process_args(int argc, char* argv[], std::map<char,string>& args)
{
    static int list_srtp_profiles = 0;
    static int list_zrtp_attributes = 0;
    static struct option long_options[] = {
        {"help", 0, nullptr, 'h'},
        {"version", 0, nullptr, 'v'},
        {"list-srtp-profiles", 0, &list_srtp_profiles, 1},
        {"list-zrtp-attributes", 0, &list_zrtp_attributes, 1},
        {nullptr, 0, nullptr, 0}
    };
#ifndef DISABLE_DAEMON_MODE
    static const char* opts = ":hvEf:x:d:D:u:g:P:";
#else
    static const char* opts = ":hvEf:x:d:D:";
#endif

    int opt;
    int option_index;

    while (-1!=(opt = getopt_long(argc, argv, opts, long_options, &option_index))) {
        switch (opt) {
        case ':':
            fprintf(stderr, "%s: missing argument for option '-%c'\n", progname, optopt);
            print_usage(true);
            exit(1);

        case '?':
            fprintf(stderr, "%s: unknown option '-%c'\n", progname, optopt);
            print_usage(true);
            exit(1);

        case 'h':
            print_usage();
            exit(0);

        case 'v':
            printf("%s\n", SEMS_VERSION);
            exit(0);

        case 0:
            //long-only options
            if(list_srtp_profiles) {
                print_supported_srtp_profiles();
                exit(0);
            } else if(list_zrtp_attributes) {
                print_supported_zrtp_attributes();
                exit(0);
            }
            break;

        default:
            args[static_cast<char>(opt)] = (optarg ? optarg : "yes");
        }
    }
    return true;
}

/*static void set_default_interface(const string& iface_name)
{
  unsigned int idx=0;
  map<string,unsigned short>::iterator if_it = AmConfig.sip_if_names.find("default");
  if(if_it == AmConfig.sip_if_names.end()) {
    SIP_interface intf;
    intf.name = "default";
    AmConfig.sip_ifs.push_back(intf);
    AmConfig.sip_if_names["default"] = AmConfig.sip_ifs.size()-1;
    idx = AmConfig.sip_ifs.size()-1;
  }
  else {
    idx = if_it->second;
  }

  SIP_info* sinfo = new SIP_UDP_info();
  sinfo->local_ip = iface_name;
  AmConfig.sip_ifs.back().proto_info.push_back(sinfo);

  if_it = AmConfig.media_if_names.find("default");
  if(if_it == AmConfig.media_if_names.end()) {
    MEDIA_interface intf;
    intf.name = "default";
    AmConfig.media_ifs.push_back(intf);
    AmConfig.media_if_names["default"] = AmConfig.media_ifs.size()-1;
    idx = AmConfig.media_ifs.size()-1;
  }
  else {
    idx = if_it->second;
  }
  RTP_info* rinfo = new RTP_info();
  rinfo->local_ip = iface_name;
  AmConfig.media_ifs[idx].proto_info.push_back(rinfo);
}*/

/* Note: The function should not use logging because it is called before
   the logging is initialized. */
static bool apply_args(std::map<char,string>& args)
{
  for(std::map<char,string>::iterator it = args.begin();
      it != args.end(); ++it){

    switch( it->first ){
    /*case 'd':
      set_default_interface(it->second);
      break;*/

    case 'D':
      if(!AmConfig.log_stderr){
          /*fprintf(stderr, "%s: -D flag usage without preceding -E has no effect. force -E flag\n",
                  progname);*/
          if (!AmLcConfig::GetInstance().setLogStderr(true)) {
              return false;
          }
      }
      if (!AmLcConfig::GetInstance().setStderrLogLevel(it->second)) {
          fprintf(stderr, "%s: invalid stderr log level: %s\n",
                  progname, it->second.c_str());
          return false;
      }
      break;

    case 'E':
#ifndef DISABLE_DAEMON_MODE
     AmConfig.deamon_mode = false;
#endif
     if (!AmLcConfig::GetInstance().setLogStderr(true)) {
       return false;
     }
     break;

    case 'f':
      AmLcConfig::GetInstance().config_path = it->second;
      break;

    case 'x':
      AmConfig.modules_path = it->second;
      break;

#ifndef DISABLE_DAEMON_MODE
    case 'P':
      AmConfig.deamon_pid_file = it->second;
      break;

    case 'u':
      AmConfig.deamon_uid = it->second;
      break;

    case 'g':
      AmConfig.deamon_gid = it->second;
      break;
#endif

    case 'h':
    case 'v':
    default:
      /* nothing to apply */
      break;
    }
  }

  return true;
}

/** Flag to mark the shutdown is in progress (in the main process) */
static AmCondition<bool> is_shutting_down(false);

class ConfigReloadTimer : public timer
{
public:
    ConfigReloadTimer() : timer(wheeltimer::instance()->wall_clock){}
    void fire() override
    {
        ConfigContainer cfg_box;
        if(AmLcConfig::GetInstance().readConfiguration(&cfg_box)) {
            ERROR("configuration errors. reconfiguration stopped");
            return;
        }

        AmArg ret;
        AmPlugIn::instance()->listFactories4Config(ret);
        for(size_t i = 0; i < ret.size(); i++) {
            AmArg &factory_name = ret[i];
            if(!isArgCStr(factory_name))
                continue;
            AmConfigFactory* factory = AmPlugIn::instance()->getFactory4Config(factory_name.asCStr());
            if(factory && factory->reconfigure(cfg_box.module_config[factory_name.asCStr()])) {
                ERROR("configuration failed. reconfiguration stopped");
                return;
            }
        }
    }
};

static void signal_handler(int sig)
{
  if(sig == SIGUSR1) {
    AmSessionContainer::instance()->broadcastShutdown();
    return;
  }

  if(sig == SIGUSR2) {
    DBG("brodcasting User event to %u sessions...\n",
	AmSession::getSessionNum());
    AmEventDispatcher::instance()->broadcast(new AmSystemEvent(AmSystemEvent::User));
    return;
  }

  if (sig == SIGCHLD && AmConfig.ignore_sig_chld) {
    return;
  }

  if (sig == SIGPIPE && AmConfig.ignore_sig_pipe) {
    return;
  }

  WARN("Signal %s (%d) received.\n", strsignal(sig), sig);

  if(sig == SIGQUIT) {
    CoreRpc::set_system_shutdown(!AmConfig.shutdown_mode);
    return;
  }

  if (sig == SIGHUP) {
    wheeltimer::instance()->insert_timer(new ConfigReloadTimer());
    return;
  }

  if (sig == SIGTERM) {
    AmSessionContainer::instance()->enableUncleanShutdown();
  }

  if (main_pid == getpid()) {
    if(!is_shutting_down.get()) {
      is_shutting_down.set(true);

      INFO("Stopping SIP stack after signal\n");
      sip_ctrl.stop();
    }
  }
  else {
    /* exit other processes immediately */
    exit(0);
  }
}

int set_sighandler(void (*handler)(int))
{
  static int sigs[] = {
    SIGHUP, SIGPIPE, SIGINT, SIGTERM, SIGQUIT, SIGCHLD, SIGUSR1, SIGUSR2, 0
  };

  for (int* sig = sigs; *sig; sig++) {
    if (signal(*sig, handler) == SIG_ERR ) {
      ERROR("Cannot install signal handler for %s.\n", strsignal(*sig));
      return -1;
    }
  }

  return 0;
}

#ifndef DISABLE_DAEMON_MODE

static int write_pid_file()
{
  FILE* fpid = fopen(AmConfig.deamon_pid_file.c_str(), "w");

  if (fpid) {
    string spid = int2str((int)getpid());
    fwrite(spid.c_str(), spid.length(), 1, fpid);
    fclose(fpid);
    return 0;
  }
  else {
    ERROR("Cannot write PID file '%s': %s.\n",
        AmConfig.deamon_pid_file.c_str(), strerror(errno));
  }

  return -1;
}

#endif /* !DISABLE_DAEMON_MODE */

int set_fd_limit()
{
  struct rlimit rlim;
  if(getrlimit(RLIMIT_NOFILE,&rlim) < 0) {
    ERROR("getrlimit: %s\n",strerror(errno));
    return -1;
  }

  rlim.rlim_cur = rlim.rlim_max;

  if(setrlimit(RLIMIT_NOFILE,&rlim) < 0) {
    ERROR("setrlimit: %s\n",strerror(errno));
    return -1;
  }
 
  INFO("Open FDs limit has been raised to %u",
       (unsigned int)rlim.rlim_cur);
 
  return 0;
}

static void log_handler(srtp_log_level_t level, const char *msg, void *data)
{
    switch (level) {
    case srtp_log_level_error:
        ERROR("SRTP-LOG: %s\n", msg);
        break;
    case srtp_log_level_warning:
        WARN("SRTP-LOG: %s\n", msg);
        break;
    case srtp_log_level_info:
        INFO("SRTP-LOG: %s\n", msg);
        break;
    case srtp_log_level_debug:
//        DBG("SRTP-LOG: %s\n", msg);
        break;
    }
}

/*
 * Main
 */
int main(int argc, char* argv[])
{
  int success = false;
  size_t ret;
  std::map<char,string> args;
  #ifndef DISABLE_DAEMON_MODE
  int fd[2] = {0,0};
  #endif

  (void)ret;

  start_time = time(nullptr);
  progname = strrchr(argv[0], '/');
  progname = (progname == nullptr ? argv[0] : progname + 1);

  if(!process_args(argc, argv, args)){
    print_usage(true);
    return 1;
  }

  init_logging(SEMS_APP_NAME);

  /* apply command-line options */
  if(!apply_args(args)){
    print_usage(true);
    goto error;
  }

  /* load and apply configuration file */
  if(AmLcConfig::GetInstance().readConfiguration())
  {
    ERROR("configuration errors. exiting.");
    return -1;
  }

  /* re-apply command-line options to override configuration file */
  if(!apply_args(args)){
    goto error;
  }

  if(AmLcConfig::GetInstance().finalizeIpConfig() < 0)
    goto error;

  printf("Configuration:\n"
#ifdef _DEBUG
         "       syslog log level:    %s (%i)\n"
         "       log to stderr:       %s\n"
#endif
	 "       configuration file:  %s\n"
	 "       plug-in path:        %s\n"
#ifndef DISABLE_DAEMON_MODE
         "       daemon mode:         %s\n"
         "       daemon UID:          %s\n"
         "       daemon GID:          %s\n"
#endif
	 "\n",
#ifdef _DEBUG
	 log_level2str[AmConfig.log_level], AmConfig.log_level,
         AmConfig.log_stderr ? "yes" : "no",
#endif
	 AmLcConfig::GetInstance().config_path.c_str(),
	 AmConfig.modules_path.c_str()
#ifndef DISABLE_DAEMON_MODE
	 ,AmConfig.deamon_mode ? "yes" : "no",
	 AmConfig.deamon_uid.empty() ? "<not set>" : AmConfig.deamon_uid.c_str(),
	 AmConfig.deamon_gid.empty() ? "<not set>" : AmConfig.deamon_gid.c_str()
#endif
	);

  AmLcConfig::GetInstance().dump_Ifs();

  printf("-----BEGIN CFG DUMP-----\n"
         "%s\n"
         "-----END CFG DUMP-----\n",
         AmLcConfig::GetInstance().serialize().c_str());

  if(set_fd_limit() < 0) {
    WARN("could not raise FD limit");
  }

#ifndef DISABLE_DAEMON_MODE

  if(AmConfig.deamon_mode){
#ifdef PROPAGATE_COREDUMP_SETTINGS
    struct rlimit lim;
    bool have_limit = false;
    if (getrlimit(RLIMIT_CORE, &lim) == 0) have_limit = true;
    int dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
#endif

    if(!AmConfig.deamon_gid.empty()){
      unsigned int gid;
      if(str2i(AmConfig.deamon_gid, gid)){
	struct group* grnam = getgrnam(AmConfig.deamon_gid.c_str());
	if(grnam != NULL){
	  gid = grnam->gr_gid;
	}
	else{
	  ERROR("Cannot find group '%s' in the group database.\n",
		AmConfig.deamon_gid.c_str());
	  goto error;
	}
      }
      if(setgid(gid)<0){
	ERROR("Cannot change GID to %i: %s.",
	      gid,
	      strerror(errno));
	goto error;
      }
    }

    if(!AmConfig.deamon_uid.empty()){
      unsigned int uid;
      if(str2i(AmConfig.deamon_uid, uid)){
	struct passwd* pwnam = getpwnam(AmConfig.deamon_uid.c_str());
	if(pwnam != NULL){
	  uid = pwnam->pw_uid;
	}
	else{
	  ERROR("Cannot find user '%s' in the user database.\n",
		AmConfig.deamon_uid.c_str());
	  goto error;
	}
      }
      if(setuid(uid)<0){
	ERROR("Cannot change UID to %i: %s.",
	      uid,
	      strerror(errno));
	goto error;
      }
    }

#if defined(__linux__)
    if(!AmConfig.deamon_uid.empty() || !AmConfig.deamon_gid.empty()){
      if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0) {
	WARN("unable to set daemon to dump core after setuid/setgid\n");
      }
    }
#endif

    /* fork to become!= group leader*/
    if (pipe(fd) == -1) { /* Create a pipe */
        ERROR("Cannot create pipe.\n");
        goto error;
    }
    int pid;
    if ((pid=fork())<0){
      ERROR("Cannot fork: %s.\n", strerror(errno));
      goto error;
    }else if (pid!=0){
      close(fd[1]);
      /* parent process => wait for result from child*/
      for(int i=0;i<2;i++){
        DBG("waiting for child[%d] response\n", i);
        ret = read(fd[0], &pid, sizeof(int));
        if(pid<0){
          ERROR("Child [%d] return an error: %d\n", i, pid);
          close(fd[0]);
          goto error;
        }
        DBG("child [%d] pid:%d\n", i, pid);
      }
      DBG("all children return OK. bye world!\n");
      close(fd[0]);
      return 0;
    }else {
      /* child */
      close(fd[0]);
      main_pid = getpid();
      DBG("hi world! I'm child [%d]\n", main_pid);
      ret = write(fd[1], &main_pid, sizeof(int));
    }
    /* become session leader to drop the ctrl. terminal */
    if (setsid()<0){
      ERROR("setsid failed: %s.\n", strerror(errno));
    }
    /* fork again to drop group  leadership */
    if ((pid=fork())<0){
      ERROR("Cannot fork: %s.\n", strerror(errno));
      goto error;
    }else if (pid!=0){
      /*parent process => exit */
      close(fd[1]);
      main_pid = getpid();
      DBG("I'm out. pid: %d", main_pid);
      return 0;
    }
	
    if(write_pid_file()<0) {
      goto error;
    }

#ifdef PROPAGATE_COREDUMP_SETTINGS
    if (have_limit) {
      if (setrlimit(RLIMIT_CORE, &lim) < 0) ERROR("failed to set RLIMIT_CORE\n");
      if (prctl(PR_SET_DUMPABLE, dumpable, 0, 0, 0)<0) ERROR("cannot re-set core dumping to %d!\n", dumpable);
    }
#endif

    /* try to replace stdin, stdout & stderr with /dev/null */
    if (freopen("/dev/null", "r", stdin)==0){
      ERROR("Cannot replace stdin with /dev/null: %s.\n",
	    strerror(errno));
      /* continue, leave it open */
    };
    if (freopen("/dev/null", "w", stdout)==0){
      ERROR("Cannot replace stdout with /dev/null: %s.\n",
	    strerror(errno));
      /* continue, leave it open */
    };
    /* close stderr only if log_stderr=0 */
    if ((!AmConfig.log_stderr) && (freopen("/dev/null", "w", stderr)==0)){
      ERROR("Cannot replace stderr with /dev/null: %s.\n",
	    strerror(errno));
      /* continue, leave it open */
    };
  }

#endif /* DISABLE_DAEMON_MODE */

  main_pid = getpid();

  init_random();

  if(set_sighandler(signal_handler))
    goto error;
    
  if(AmConfig.enable_srtp) {
        if(srtp_init() != srtp_err_status_ok) {
            ERROR("Cannot initialize SRTP library\n");
            goto error;
        }
        srtp_install_log_handler(log_handler, NULL);
  }

  if(AmConfig.enable_rtsp){
    if(RtspClient::instance()->onLoad()){
      ERROR("Cannot initialize RTSP client\n");
      goto error;
    }
    DBG("sizeof(RtspAudio) = %zd",sizeof(RtspAudio));
  }
    
  AmThreadWatcher::instance();
  if(CoreRpc::instance().onLoad()) {
    ERROR("failed to initialize CoreRpc");
    goto error;
  }

  INFO("Starting application timer scheduler\n");
  AmAppTimer::instance()->start();
  AmThreadWatcher::instance()->add(AmAppTimer::instance());

  INFO("Starting session container\n");
  AmSessionContainer::instance()->start();

#ifdef SESSION_THREADPOOL
  INFO("Starting session processor threads\n");
  AmSessionProcessor::addThreads(AmConfig.session_proc_threads);
#endif 
  AmSessionProcessor::init();

  INFO("Starting audio recorder");
  AmAudioFileRecorderProcessor::instance()->start();

  INFO("Starting pcap recorder");
  PcapFileRecorderProcessor::instance()->start();

  INFO("Starting media processor\n");
  AmMediaProcessor::instance()->init();

  INFO("Starting stun processor\n");
  stun_processor::instance()->start();

  // init thread usage with libevent
  // before it's too late
  if(evthread_use_pthreads() != 0) {
    ERROR("cannot init thread usage with libevent");
    goto error;
  }

  // start the asynchronous file writer (sorry, no better place...)
  //async_file_writer::instance()->start();

  INFO("Starting RTP receiver\n");
  AmRtpReceiver::instance()->start();

  INFO("Starting SIP stack (control interface)\n");
  if(sip_ctrl.load()) {
    goto error;
  }
  
  INFO("Loading plug-ins\n");
  AmPlugIn::instance()->init();
  if(AmPlugIn::instance()->load(AmConfig.modules_path, AmConfig.modules))
    goto error;

  AmPlugIn::instance()->registerLoggingPlugins();

  AmSessionContainer::instance()->initMonitoring();

  stat_group(Counter, "core", "localtime").addFunctionCounter(
    []()->unsigned long long{
        return static_cast<unsigned long long>(time(nullptr));
    });

  stat_group(Counter, "core", "uptime").addFunctionCounter(
    []()->unsigned long long{
        return static_cast<unsigned long long>(time(nullptr) - start_time);
    });

  stat_group(Gauge, "core", "version").addFunctionCounter(
    []()->unsigned long long{
        return 1;
    }).addLabel("core", SEMS_VERSION);

  stat_group(Gauge, "core", "shutdown_mode").addFunctionCounter(
    []()->unsigned long long{
        return AmConfig.shutdown_mode == true ? 1 : 0;
    });

  if(AmConfig.session_limit) {
    stat_group(Gauge, "core", "sessions_limit").addFunctionCounter(
        []()->unsigned long long{
            return AmConfig.session_limit;
        });
  }

  stat_group(Counter, "core", "start_time").addAtomicCounter().set(
    static_cast<unsigned long long>(start_time));

  #ifndef DISABLE_DAEMON_MODE
  if(fd[1]) {
    DBG("hi world! I'm main child [%d]\n", main_pid);
    ret = write(fd[1], &main_pid, sizeof(int));
    close(fd[1]); fd[1] = 0;
  }
  #endif

  // running the server
  if(sip_ctrl.run() != -1)
    success = true;

 error:
  // session container stops active sessions
  INFO("Disposing session container\n");
  AmSessionContainer::dispose();

  /*INFO("Disposing app timer\n");
  AmAppTimer::dispose();*/
  
  DBG("** Transaction table dump: **\n");
  dumps_transactions();
  DBG("*****************************\n");

  cleanup_transaction();
  
  if(AmConfig.enable_rtsp){
    INFO("Disposing RTSP client");
    RtspClient::dispose();
  }

  INFO("Disposing RTP receiver\n");
  AmRtpReceiver::dispose();

  INFO("Disposing media processor\n");
  AmMediaProcessor::dispose();

  INFO("Disposing stun processor\n");
  stun_processor::dispose();

  INFO("Disposing audio file recorder\n");
  AmAudioFileRecorderProcessor::dispose();
  
  INFO("Disposing pcap file recorder\n");
  PcapFileRecorderProcessor::dispose();
  
  INFO("Disposing event dispatcher\n");
  AmEventDispatcher::dispose();

  //async_file_writer::instance()->stop();
  //async_file_writer::instance()->join();

#ifndef DISABLE_DAEMON_MODE
  if (AmConfig.deamon_mode) {
    unlink(AmConfig.deamon_pid_file.c_str());
  }
  if(fd[1]){
     main_pid = -1;
     DBG("send -1 to parent\n");
     ret = write(fd[1], &main_pid, sizeof(int));
     close(fd[1]);
  }
#endif

  sip_ctrl.cleanup();
  resolver::instance()->clear_cache();
  resolver::dispose();
  SipCtrlInterface::dispose();
  tr_blacklist::dispose();

  AmThreadWatcher::instance()->cleanup();

  INFO("Disposing plug-ins\n");
  AmPlugIn::dispose();

  tls_cleanup();
  srtp_shutdown();
  statistics::dispose();
#if EVENT__NUMERIC_VERSION>0x02010000
  libevent_global_shutdown();
#endif
  
  INFO("Exiting (%s)\n", success ? "success" : "failure");
  
  return (success ? EXIT_SUCCESS : EXIT_FAILURE);
}

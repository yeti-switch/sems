#include "AmPlugIn.h"
#include "AmLcConfig.h"
#include "log.h"
#include "DILog.h"


#include <iostream>
#include <fstream>
#include <sstream>

#include <stdarg.h>

using namespace std;

#define MOD_NAME "di_log"
#include "log.h"

#define PARAM_LOG_LEVEL_NAME "loglevel"

EXPORT_LOG_FACILITY_FACTORY(DILog);
EXPORT_PLUGIN_CONF_FACTORY(DILog);
EXPORT_PLUGIN_CLASS_FACTORY(DILog);
DEFINE_FACTORY_INSTANCE(DILog, MOD_NAME);

char DILog::ring_buf[MAX_LINES][MAX_LINE_LEN] = {{0}};
int DILog::pos = 0;

DILog::DILog(const string& name)
    : AmDynInvokeFactory(name),
      AmLoggingFacility(name, MODULE_VERSION, L_DBG),
      AmConfigFactory(name, name)
{ }

int DILog::onLoad() {
  DBG("DILog logging ring-buffer loaded.\n");
  return 0;
}

DILog::~DILog() { }

void DILog::invoke(const string& method, const AmArg& args, AmArg& ret) {
  if(method == "dumplog") {
    ret.push(dumpLog().c_str());
  } else if(method == "dumplogtodisk") {
    dumpLog(args.get(0).asCStr(),ret);
  } else if(method == "help") {
    ret.push("dumplog\n"
	     "dumplogtodisk <path>\n"
	     );
  } else throw AmDynInvoke::NotImplemented(method);
}

void DILog::dumpLog(const char* path, AmArg &ret) {
  ostringstream ss;
  fstream fs(path, ios::out);
  if(!fs.is_open()){
    ss << "can't open file '" << path << "' for writing";
    ret = ss.str();
    return;
  }
  int start = (pos + 1) % MAX_LINES;
  for(int i=0; i<MAX_LINES; i++) {
    fs << ring_buf[(i+start)%MAX_LINES];
  }
  ss << "dumped to '" << path << "'";
  ret = ss.str();
}

string DILog::dumpLog() {
  stringstream log;

  int start = (pos + 1) % MAX_LINES;
  for(int i=0; i<MAX_LINES; i++) {
    log << ring_buf[(i+start)%MAX_LINES];
  }
  log << endl;
  return log.str();
}

void DILog::log(
    int level, pid_t pid, pid_t tid,
    const char* func, const char* file, int line, const char* msg)
{
  char ts[26];
  struct timeval tv;
  struct tm t;

  gettimeofday(&tv,NULL);
  localtime_r(&tv.tv_sec,&t);
  strftime(ts, 26, "%b %d %T",&t);

  snprintf(ring_buf[pos],MAX_LINE_LEN,"%s [%u:%u/%s:%d] %s: %s\n",
    ts,/*ctime_r(&tv.tv_sec, ts),*/
    pid,tid,
    file,line,
    log_level2str[level], msg
  );
  //strncpy(ring_buf[pos], msg, sizeof(ring_buf[0]));
  pos = (pos + 1) % MAX_LINES;
}

int DILog::configure(const std::string& config)
{
    cfg_opt_t di_opt[]
    {
        CFG_STR(PARAM_LOG_LEVEL_NAME, 0, CFGF_NODEFAULT),
        CFG_END()
    };
    cfg_t *cfg = cfg_init(di_opt, CFGF_NONE);
    if(!cfg) return -1;
    cfg_set_validate_func(cfg, PARAM_LOG_LEVEL_NAME, validate_log_func);

    switch(cfg_parse_buf(cfg, config.c_str())) {
    case CFG_SUCCESS:
        break;
    case CFG_PARSE_ERROR:
        ERROR("configuration of module %s parse error",MOD_NAME);
        cfg_free(cfg);
        return -1;
    default:
        ERROR("unexpected error on configuration of module %s processing",MOD_NAME);
        cfg_free(cfg);
        return -1;
    }

    if(cfg_size(cfg, PARAM_LOG_LEVEL_NAME))
        setLogLevel(parse_log_level(cfg_getstr(cfg, PARAM_LOG_LEVEL_NAME)));

    cfg_free(cfg);
    return 0;
}

int DILog::reconfigure(const std::string& config)
{
    return configure(config);
}

// TODO: new() array on load, provide DI for resizing

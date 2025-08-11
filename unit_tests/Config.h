#ifndef CONFIG_H
#define CONFIG_H

#include <map>
#include <set>
#include <vector>
#include <confuse.h>
#include "singleton.h"
#include "AmArg.h"

using std::map;
using std::set;
using std::vector;

class TesterConfig {
  public:
    // optimization parameter;
    struct parameter_var {
        enum { String, Bool, Integer } type;
        union {
            void   *p_void;
            string *p_str;
            int    *p_int;
            bool   *p_bool;
        } u;
    };
    typedef map<string, parameter_var> ConfigParameters;

  protected:
    ConfigParameters    config_parameters;
    map<string, string> modules_cfg;
    set<string>         cmd_unknown_parameters;

  public:
    TesterConfig();
    ~TesterConfig();
    void dispose() {}

    int readConfiguration(const string &filePath);
    int parseCmdOverride(const string &param);

    AmArg configureModule(const string &moduleName, cfg_opt_t *opt);
    void  useCmdModule(map<string, parameter_var> config_parameters);

    vector<string> allow_plugins;
    string         signalling_interface;
    int            stress_session_duration;
    int            stress_session_pairs_count;
    string         stress_media_codec;
    int            log_level;
};

typedef singleton<TesterConfig> test_config;

#endif /*CONFIG_H*/

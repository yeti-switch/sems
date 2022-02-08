#ifndef CONFIG_H
#define CONFIG_H

#include <map>
#include <vector>
#include "singleton.h"

using std::vector;
using std::map;

class TesterConfig
{
    //optimization parameter;
    struct parameter_var
    {
        enum {
            String,
            Integer
        } type;
        union {
            void*   p_void;
            string* p_str;
            int*    p_int;
        } u;
    };
    map<string, parameter_var> config_parameters;
public:
    TesterConfig();
    ~TesterConfig();

    int readConfiguration(const string& filePath);
    int parseCmdOverride(const string& param);

    string signalling_interface;
    int stress_session_duration;
    int stress_session_pairs_count;
    string stress_media_codec;
    int http_port;
    string http_destination;
    int log_level;
    vector<string> allow_plugins;
};

typedef singleton<TesterConfig> test_config;

#endif/*CONFIG_H*/

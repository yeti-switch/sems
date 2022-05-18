#include "Config.h"
#include <confuse.h>
#include "AmLcConfig.h"

extern int validate_log_func(cfg_t *cfg, cfg_opt_t *opt);
extern int parse_log_level(const std::string& level);

#define PARAM_SEMS_CONFIG_PATH_NAME "sems_config_path"
#define PARAM_SIG_INTERFACE_NAME    "signalling_interface_name"
#define PARAM_SESSION_DURATION_NAME "session_duration"
#define PARAM_MEDIA_CODEC_NAME      "media_codec"
#define PARAM_PAIRS_COUNT_NAME      "sessions_pairs_count"
#define PARAM_ALLOW_PLUGINS_NAME    "allow_plugins"
#define PARAM_LOG_LEVEL_NAME        "log_level"
#define PARAM_HTTP_PORT_NAME        "port"
#define PARAM_HTTP_DEST_NAME        "destination"

#define SECTION_STRESS_NAME         "stress"
#define SECTION_HTTP_NAME           "http"

#define DEFAULT_LOG_LEVEL        "info"
#define DEFAULT_DURATION         100
#define DEFAULT_PAIRS_COUNT      200
#define DEFAULT_PORT             6666
#define DEFAULT_DESTINATION      "test"

TesterConfig::TesterConfig()
: stress_session_duration(DEFAULT_DURATION)
, stress_session_pairs_count(DEFAULT_PAIRS_COUNT)
{
    config_parameters.emplace<string, parameter_var>(PARAM_SEMS_CONFIG_PATH_NAME, {.type = parameter_var::String, .u = {&AmLcConfig::instance().config_path}});
    config_parameters.emplace<string, parameter_var>(PARAM_SIG_INTERFACE_NAME, {.type = parameter_var::String, .u = {&signalling_interface}});
    config_parameters.emplace<string, parameter_var>(SECTION_STRESS_NAME "_" PARAM_SESSION_DURATION_NAME, {.type = parameter_var::Integer, .u = {&stress_session_duration}});
    config_parameters.emplace<string, parameter_var>(SECTION_STRESS_NAME "_" PARAM_PAIRS_COUNT_NAME, {.type = parameter_var::Integer, .u = {&stress_session_pairs_count}});
    config_parameters.emplace<string, parameter_var>(SECTION_STRESS_NAME "_" PARAM_MEDIA_CODEC_NAME, {.type = parameter_var::String, .u = {&stress_media_codec}});
}

TesterConfig::~TesterConfig()
{
}

int TesterConfig::readConfiguration(const string& filePath)
{
    cfg_opt_t stress[] = {
        CFG_INT(PARAM_SESSION_DURATION_NAME, DEFAULT_DURATION, CFGF_NONE),
        CFG_INT(PARAM_PAIRS_COUNT_NAME, DEFAULT_PAIRS_COUNT, CFGF_NONE),
        CFG_STR(PARAM_MEDIA_CODEC_NAME, "", CFGF_NODEFAULT),
        CFG_END()
    };

    cfg_opt_t http[] = {
        CFG_INT(PARAM_HTTP_PORT_NAME, DEFAULT_PORT, CFGF_NONE),
        CFG_STR(PARAM_HTTP_DEST_NAME, DEFAULT_DESTINATION, CFGF_NONE), 
        CFG_END()
    };

    cfg_opt_t opt[] = {
        CFG_STR(PARAM_SEMS_CONFIG_PATH_NAME, AmLcConfig::instance().config_path.c_str(), CFGF_NONE),
        CFG_STR(PARAM_SIG_INTERFACE_NAME, "", CFGF_NODEFAULT),
        CFG_STR(PARAM_LOG_LEVEL_NAME, DEFAULT_LOG_LEVEL, CFGF_NONE),
        CFG_STR_LIST(PARAM_ALLOW_PLUGINS_NAME, 0, CFGF_NODEFAULT),
        CFG_SEC(SECTION_STRESS_NAME, stress, CFGF_NONE),
        CFG_SEC(SECTION_HTTP_NAME, http, CFGF_NONE),
        CFG_END()
    };

    cfg_t* m_cfg;
    m_cfg = cfg_init(opt, 0);
    cfg_set_validate_func(m_cfg, PARAM_LOG_LEVEL_NAME , validate_log_func);
    if(!m_cfg) return -1;

    switch(cfg_parse(m_cfg, filePath.c_str())) {
    case CFG_SUCCESS:
        break;
    case CFG_FILE_ERROR:
        ERROR("failed to open configuration file: %s (%s)",
            filePath.c_str(), strerror(errno));
        return -1;
    case CFG_PARSE_ERROR:
        ERROR("failed to parse configuration file: %s", filePath.c_str());
        return -1;
    default:
        ERROR("got unexpected error on configuration file processing: %s", filePath.c_str());
        return -1;
    }

    AmLcConfig::instance().config_path = cfg_getstr(m_cfg, PARAM_SEMS_CONFIG_PATH_NAME);
    if(!cfg_size(m_cfg, PARAM_SIG_INTERFACE_NAME)) {
        ERROR("absent signalling interface name in config");
        return -1;
    }

    signalling_interface = cfg_getstr(m_cfg, PARAM_SIG_INTERFACE_NAME);
    log_level = parse_log_level(cfg_getstr(m_cfg, PARAM_LOG_LEVEL_NAME));

    for(unsigned int i = 0; i < cfg_size(m_cfg, PARAM_ALLOW_PLUGINS_NAME); i++) {
        allow_plugins.push_back(cfg_getnstr(m_cfg, PARAM_ALLOW_PLUGINS_NAME, i));
    }

    cfg_t* m_stress = cfg_getsec(m_cfg, SECTION_STRESS_NAME);
    stress_session_duration = cfg_getint(m_stress, PARAM_SESSION_DURATION_NAME);
    stress_session_pairs_count = cfg_getint(m_stress, PARAM_PAIRS_COUNT_NAME);
    if(!cfg_size(m_stress, PARAM_MEDIA_CODEC_NAME)) {
        ERROR("absent media codec of stress test in config");
        return -1;
    }

    stress_media_codec = cfg_getstr(m_stress, PARAM_MEDIA_CODEC_NAME);

    cfg_t* m_http = cfg_getsec(m_cfg, SECTION_HTTP_NAME);
    http_port = cfg_getint(m_http, PARAM_HTTP_PORT_NAME);
    http_destination = cfg_getstr(m_http, PARAM_HTTP_DEST_NAME);
    return 0;
}

int TesterConfig::parseCmdOverride(const string& param)
{
    for(auto& parameter : config_parameters) {
        if(strncmp(param.c_str(), "--", 2) != 0) {
            ERROR("incorrect command line parameter: %s", param.c_str());
            return -1;
        }
        size_t pos = param.find(parameter.first);
        if(pos == string::npos) return 0;
        if(pos != 2) {
            ERROR("incorrect command line parameter: %s", param.c_str());
            return -1;
        }
        pos += parameter.first.size();
        if(param[pos] != '=') {
            ERROR("incorrect command line parameter: %s", param.c_str());
            return -1;
        }
        pos++;
        string value = param.c_str() + pos;
        if(parameter.second.type == parameter_var::Integer) {
            if(!str2int(value, *parameter.second.u.p_int)) {
                ERROR("parameter is not integer: %s", param.c_str());
                return -1;
            }
        } else if(parameter.second.type == parameter_var::String) {
            *parameter.second.u.p_str = value;
        }
    }
    return 1;
}

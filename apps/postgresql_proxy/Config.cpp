#include "Config.h"
#include "PostgreSqlProxy.h"

#include <fstream>
#include <string>

using std::string;

int map_func(cfg_t *cfg, cfg_opt_t *, int argc, const char **argv)
{
    if (argc < 2)
        return 1;

    const char *query    = argv[0];
    const char *response = argv[1];
    const char *error    = argc > 2 ? argv[2] : "";
    const bool  timeout  = argc > 3 ? str2bool(argv[3]).value_or(false) : false;

    return PostgreSqlProxy::instance()->insert_resp_map(query, response, error, timeout);
}

int map_file_func(cfg_t *cfg, cfg_opt_t *, int argc, const char **argv)
{
    if (argc != 2)
        return 1;

    const char *query     = argv[0];
    const char *file_path = argv[1];

    string data;
    try {
        std::ifstream f(file_path);
        if (!f) {
            DBG("failed to open: %s", file_path);
            return 1;
        }

        data = string((std::istreambuf_iterator<char>(f)), (std::istreambuf_iterator<char>()));
    } catch (...) {
        DBG("failed to load %s", file_path);
        return 1;
    }

    return PostgreSqlProxy::instance()->insert_resp_map(query, data);
}

int map_lua_func(cfg_t *cfg, cfg_opt_t *, int argc, const char **argv)
{
    if (argc != 2)
        return 1;

    const char *query     = argv[0];
    const char *file_path = argv[1];

    return PostgreSqlProxy::instance()->insert_resp_lua(query, file_path);
}

int map_upstream_func(cfg_t *cfg, cfg_opt_t *, int argc, const char **argv)
{
    if (argc != 2)
        return 1;

    const char *query = argv[0];
    const char *queue = argv[1];

    return PostgreSqlProxy::instance()->insert_upstream_mapping(query, queue);
}

int map_upstream_worker_func(cfg_t *cfg, cfg_opt_t *, int argc, const char **argv)
{
    if (argc != 2)
        return 1;

    const char *query = argv[0];
    const char *queue = argv[1];

    return PostgreSqlProxy::instance()->insert_upstream_worker_mapping(query, queue);
}

cfg_opt_t pg_opts[] = { CFG_FUNC(CFG_OPT_MAP, &map_func),
                        CFG_FUNC(CFG_OPT_MAP_FILE, &map_file_func),
                        CFG_FUNC(CFG_OPT_MAP_LUA, &map_lua_func),
                        CFG_FUNC(CFG_OPT_MAP_UPSTREAM, &map_upstream_func),
                        CFG_FUNC(CFG_OPT_MAP_UPSTREAM_WORKER, &map_upstream_worker_func),
                        CFG_BOOL(CFG_OPT_LOG_PG_EVENTS_NAME, cfg_false, CFGF_NONE),
                        CFG_STR(CFG_OPT_UPSTREAM_QUEUE, "", CFGF_NONE),
                        CFG_END() };

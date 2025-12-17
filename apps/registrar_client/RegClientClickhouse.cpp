#include "RegClientClickhouse.h"
#include <AmSessionContainer.h>
#include <HttpClientAPI.h>
#include <AmPlugIn.h>
#include <confuse.h>
#include <jsonArg.h>

#define CFG_OPT_NAME_DESTINATIONS "destinations"
#define CFG_OPT_NAME_TABLE        "table"
#define CFG_OPT_NAME_PERIOD       "period"

#define DEFAULT_TABLE_NAME "registrations"
#define DEFAULT_PERIOD     60

RegClientClickhouse::RegClientClickhouse()
    : clickhouse_enable(false)
{
}

int RegClientClickhouse::configure(const string &config)
{
    cfg_opt_t opt[] = { CFG_STR(CFG_OPT_NAME_TABLE, DEFAULT_TABLE_NAME, CFGF_NONE),
                        CFG_INT(CFG_OPT_NAME_PERIOD, DEFAULT_PERIOD, CFGF_NONE),
                        CFG_STR_LIST(CFG_OPT_NAME_DESTINATIONS, 0, CFGF_NONE), CFG_END() };
    cfg_t    *cfg   = cfg_init(opt, CFGF_NONE);
    if (!cfg)
        return -1;
    switch (cfg_parse_buf(cfg, config.c_str())) {
    case CFG_SUCCESS: break;
    case CFG_PARSE_ERROR:
        ERROR("configuration of module %s parse error", MOD_NAME);
        cfg_free(cfg);
        return -1;
    default:
        ERROR("unexpected error on configuration of module %s processing", MOD_NAME);
        cfg_free(cfg);
        return -1;
    }

    if (AmPlugIn::instance()->getFactory4Config("http_client") == nullptr) {
        WARN("disable clickhouse snapshots because http_client module is not loaded");
        return 0;
    }

    for (int i = 0; i < cfg_size(cfg, CFG_OPT_NAME_DESTINATIONS); i++)
        clickhouse_dest.push_back(cfg_getnstr(cfg, CFG_OPT_NAME_DESTINATIONS, i));
    clickhouse_table  = cfg_getstr(cfg, CFG_OPT_NAME_TABLE);
    clickhouse_period = cfg_getint(cfg, CFG_OPT_NAME_PERIOD);
    if (clickhouse_dest.empty()) {
        WARN("disable clickhouse snapshots because 'destinations' is empty");
        return 0;
    }

    snapshots_body_header = "INSERT INTO ";
    snapshots_body_header += clickhouse_table + " FORMAT JSONEachRow\n";

    clickhouse_enable = true;

    cfg_free(cfg);
    return 0;
}

int RegClientClickhouse::init(int epoll_fd)
{
    if (!clickhouse_enable)
        return 0;

    clickhouse_timer.link(epoll_fd);
    clickhouse_timer.set(clickhouse_period * 1000000 /* seconds */, true);

    return 0;
}

void RegClientClickhouse::on_timer()
{
    string data = snapshots_body_header;

    time_t snapshot_ts;
    time(&snapshot_ts);
    snapshot_ts = snapshot_ts - (snapshot_ts % clickhouse_period);
    if (last_snapshot_ts && last_snapshot_ts == snapshot_ts) {
        ERROR("duplicate snapshot %lu timestamp. "
              "ignore timer event (can lead to time gap between snapshots)",
              snapshot_ts);
        return;
    }
    struct tm snapshot_tm;
    localtime_r(&snapshot_ts, &snapshot_tm);
    char strftime_buf[32];
    strftime(strftime_buf, sizeof strftime_buf, "%F %T", &snapshot_tm);

    snapshot_id.fields.timestamp = snapshot_ts;
    snapshot_id.fields.counter++;

    AmArg snapshot;
    getSnapshot(snapshot, [&](unsigned long long value, AmArg &data) {
        data["state"]              = static_cast<unsigned int>(value);
        data["snapshot_id"]        = snapshot_id.v;
        data["snapshot_timestamp"] = strftime_buf;
        data["node_id"]            = AmConfig.node_id;
    });

    if (!snapshot.size())
        return;

    for (unsigned int i = 0; i < snapshot.size(); i++)
        data += arg2json(snapshot[i]) + "\n";

    // DBG("data:\n%s", data.c_str());

    for (const auto &dest : clickhouse_dest) {
        AmSessionContainer::instance()->postEvent(HTTP_EVENT_QUEUE, new HttpPostEvent(dest, data, string()));
    }
}

#include "RegistrarClickhouse.h"
#include <AmPlugIn.h>
#include <jsonArg.h>
#include <HttpClientAPI.h>
#include <AmSessionContainer.h>

RegistrarClickhouse::RegistrarClickhouse()
    : clickhouse_enable(false)
    , last_snapshot_ts(0)
{
    snapshot_id.fields.sign    = 0;
    snapshot_id.fields.node_id = AmConfig.node_id;
    snapshot_id.fields.counter = 0;
}

int RegistrarClickhouse::configure(cfg_t *cfg)
{
    cfg_t *clickhouse = cfg_getsec(cfg, CFG_SEC_CLICKHOUSE);
    if (!clickhouse) {
        DBG("disable clickhouse snapshots because of absent clickhouse section in config");
        return 0;
    }

    if (AmPlugIn::instance()->getFactory4Config("http_client") == nullptr) {
        WARN("disable clickhouse snapshots because http_client module is not loaded");
        return 0;
    }

    for (int i = 0; i < cfg_size(clickhouse, CFG_PARAM_DESTINATIONS); i++)
        clickhouse_dest.push_back(cfg_getnstr(clickhouse, CFG_PARAM_DESTINATIONS, i));
    clickhouse_table  = cfg_getstr(clickhouse, CFG_PARAM_TABLE);
    clickhouse_period = cfg_getint(clickhouse, CFG_PARAM_PERIOD);
    if (clickhouse_dest.empty()) {
        DBG("disable clickhouse snapshots because 'destinations' is empty");
        return 0;
    }

    snapshots_body_header = "INSERT INTO ";
    snapshots_body_header += clickhouse_table + " FORMAT JSONEachRow\n";

    clickhouse_enable = true;

    return 0;
}

int RegistrarClickhouse::init(int epoll_fd)
{
    if (!clickhouse_enable)
        return 0;

    clickhouse_timer.link(epoll_fd);
    clickhouse_timer.set(clickhouse_period * 1000000 /* seconds */, true);

    return 0;
}

void RegistrarClickhouse::on_timer()
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
    getSnapshot(snapshot, [&](AmArg &data) {
        data["snapshot_id"]        = snapshot_id.v;
        data["snapshot_timestamp"] = strftime_buf;
    });

    if (!snapshot.size())
        return;

    for (unsigned int i = 0; i < snapshot.size(); i++)
        data += arg2json(snapshot[i]) + "\n";

    // DBG("data:\n%s",data.c_str());

    for (const auto &dest : clickhouse_dest) {
        AmSessionContainer::instance()->postEvent(HTTP_EVENT_QUEUE, new HttpPostEvent(dest, data, string()));
    }
}

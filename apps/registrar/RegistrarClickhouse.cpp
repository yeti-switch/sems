#include "RegistrarClickhouse.h"
#include <AmPlugIn.h>
#include <jsonArg.h>
#include <HttpClientAPI.h>
#include <AmSessionContainer.h>

RegistrarClickhouse::RegistrarClickhouse()
  : clickhouse_enable(false)
{
}

int RegistrarClickhouse::configure(cfg_t* cfg)
{
    cfg_t* clickhouse = cfg_getsec(cfg, CFG_SEC_CLICKHOUSE);
    if(!clickhouse) {
        DBG("disable clickhouse snapshots because of absent clickhouse section in config");
        return 0;
    }

    if (AmPlugIn::instance()->getFactory4Config("http_client") == nullptr) {
        WARN("disable clickhouse snapshots because http_client module is not loaded");
        return 0;
    }

    for(int i= 0; i < cfg_size(clickhouse, CFG_PARAM_DESTINATIONS); i++)
        clickhouse_dest.push_back(cfg_getnstr(clickhouse, CFG_PARAM_DESTINATIONS, i));
    clickhouse_table = cfg_getstr(clickhouse, CFG_PARAM_TABLE);
    clickhouse_period = cfg_getint(clickhouse, CFG_PARAM_PERIOD);
    if(clickhouse_dest.empty()) {
        WARN("disable clickhouse snapshots because 'destinations' is empty");
        return 0;
    }

    snapshots_body_header = "INSERT INTO ";
    snapshots_body_header += clickhouse_table + " FORMAT JSONEachRow\n";

    clickhouse_enable = true;

    return 0;
}

int RegistrarClickhouse::init(int epoll_fd)
{
    if(!clickhouse_enable) return 0;

    clickhouse_timer.link(epoll_fd);
    clickhouse_timer.set(clickhouse_period * 1000000 /* seconds */,true);

    return 0;
}

void RegistrarClickhouse::on_timer()
{
    string data = snapshots_body_header;

    AmArg snapshot;
    getSnapshot(snapshot);

    if(!snapshot.size())
        return;

    for(unsigned int i = 0;i < snapshot.size();i++)
        data+=arg2json(snapshot[i])+"\n";

    //DBG("data:\n%s",data.c_str());

    for(const auto &dest: clickhouse_dest) {
        AmSessionContainer::instance()->postEvent(
            HTTP_EVENT_QUEUE,
            new HttpPostEvent(
                dest,
                data,
                string()));
    }
}



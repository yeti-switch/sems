#pragma once

#include <string>
#include <vector>
#include <memory>

using std::string;
using std::vector;

#include "SipRegistrarConfig.h"


class RegistrarClickhouse
  : public virtual Configurable
{
  protected:
    bool clickhouse_enable;
    string clickhouse_table;
    vector<string> clickhouse_dest;
    int clickhouse_period;

    AmTimerFd clickhouse_timer;
    string snapshots_body_header;
  public:
    RegistrarClickhouse();
    virtual ~RegistrarClickhouse(){}

    int configure(cfg_t* cfg) override;

    int init(int epoll_fd);
    void on_timer();

    virtual void getSnapshot(AmArg& data) = 0;
};

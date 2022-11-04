#pragma once

#include "Connection.h"

class PGConnection
  : public Connection
{
    PGconn* conn;
    bool connected;

    bool reset_conn() override;
    void check_conn() override;
    bool flush_conn(bool flush_pipe = false) override;
    PGconn* get_pg_conn() override;
    void close_conn() override;
    bool start_pipe() override;
    bool sync_pipe() override;
    bool exit_pipe() override;
public:
    PGConnection(const string& conn_info, const string& conn_log_info, IConnectionHandler* handler);
    ~PGConnection();

};

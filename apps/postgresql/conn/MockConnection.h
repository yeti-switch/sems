#pragma once

#include "Connection.h"

class MockConnection : public Connection {
    int conn_fd;

    bool reset_conn() override;
    void check_conn() override;
    bool flush_conn() override;
    void close_conn() override;
    bool start_pipe() override;
    bool sync_pipe() override;
    bool exit_pipe() override;
    bool flush_pipe() override;

  public:
    MockConnection(IConnectionHandler *handler);
    ~MockConnection();

    int getSocket() override { return conn_fd; }
};

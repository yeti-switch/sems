#pragma once

#include "Connection.h"

class MockConnection : public Connection
{
    bool reset_conn() override;
    void check_conn() override;
    bool flush_conn(bool flush_pipe = false) override;
    void close_conn() override;
    bool start_pipe() override;
    bool sync_pipe() override;
    bool exit_pipe() override;
public:
    MockConnection(IConnectionHandler* handler);
    ~MockConnection();
};

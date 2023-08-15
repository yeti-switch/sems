#pragma once

#include "IConnectionHandler.h"

#include <postgresql/libpq-fe.h>
#include <ctime>
#include <atomic_types.h>

#include <string>
using std::string;

class Connection
{
protected:
    string connection_info;
    string connection_log_info;
    IConnectionHandler* handler;
    ConnStatusType status;
    PGpipelineStatus pipe_status;
    bool is_pipeline;
    int conn_fd;
    time_t connected_time;
    time_t disconnected_time;
    uint64_t queries_finished;

    friend class Transaction;
    Transaction* cur_transaction;
    Transaction* planned;

    void check_mode();

    virtual void check_conn() = 0;
    virtual PGconn* get_pg_conn() { return nullptr; }
    virtual bool flush_conn() = 0;
    virtual bool reset_conn() = 0;
    virtual void close_conn() = 0;
    virtual bool start_pipe() = 0;
    virtual bool exit_pipe()  = 0;
    virtual bool sync_pipe() = 0;
    virtual bool flush_pipe() = 0;

public:
    Connection(const string& conn_info, const string& conn_log_info, IConnectionHandler* handler)
    : connection_info(conn_info)
    , connection_log_info(conn_log_info)
    , handler(handler)
    , status(CONNECTION_BAD), pipe_status(PQ_PIPELINE_OFF)
    , is_pipeline(false)
    , conn_fd(-1)
    , connected_time(0)
    , disconnected_time(::time(0))
    , queries_finished(0)
    , cur_transaction(nullptr)
    , planned(nullptr)
    {}
    virtual ~Connection();

    operator PGconn * () { return get_pg_conn(); }

    void check();
    bool reset();
    void close();
    bool flush();
    bool runTransaction(Transaction* trans);
    bool addPlannedTransaction(Transaction* trans);
    void startPipeline();
    bool syncPipeline();
    bool flushPipeline();
    void exitPipeline();
    void stopTransaction();
    void cancelTransaction();
    ConnStatusType getStatus() { return status; }
    PGpipelineStatus getPipeStatus() { return pipe_status; }
    int getSocket() { return conn_fd; }
    string getConnInfo() { return connection_log_info; }
    bool isBusy() { return cur_transaction ? true : (status != CONNECTION_OK); }
    time_t getDisconnectedTime() const { return disconnected_time; }
    time_t getConnectedTime() { return connected_time; }
    uint64_t getQueriesFinished() { return queries_finished; }
    Transaction* getCurrentTransaction() { return cur_transaction; }
};

#include "PGConnection.h"
#include <cstring>

PGConnection::PGConnection(const std::string& conn_info, const string& conn_log_info, IConnectionHandler* handler)
  : Connection(conn_info, conn_log_info, handler),
    conn(0),
    connected(false)
{}

PGConnection::~PGConnection()
{
    PGConnection::close_conn();
}

void PGConnection::check_conn()
{
    if(!handler) return;

    if(connected) {
        //DBG("PQconsumeInput");
        if(!PQconsumeInput(conn)) {
            disconnected_time = time(0);
            connected_time = 0;
            close_conn();
            return;
        }
        PGnotify* notify =  PQnotifies(conn);
        if(notify) {
            //DBG("notification");
            PQfreemem(notify);
        }
    }

    PostgresPollingStatusType   st = PQconnectPoll(conn);
    status = PQstatus(conn);
    pipe_status = PQpipelineStatus(conn);
    //DBG("check status %u, poll_st %u, pipe %s", status, st, pipe_status == PQ_PIPELINE_ON ? "true" : "false");
    switch((int)st) {
        case PGRES_POLLING_OK:
            flush_conn();
            if(!connected && status == CONNECTION_OK) {
                connected = true;
                //PQtrace(conn, stderr);
                PQsetErrorVerbosity(conn, PQERRORS_VERBOSE);
                handler->onConnect(this);
            }
        case PGRES_POLLING_READING:
            if(connected && cur_transaction) {
                flush_conn();
            } else {
                handler->onSock(this, IConnectionHandler::PG_SOCK_READ);
            }
            break;
        case PGRES_POLLING_WRITING:
            handler->onSock(this, IConnectionHandler::PG_SOCK_WRITE);
            break;
        case PGRES_POLLING_FAILED:
            status = CONNECTION_BAD;
            break;
    }

    if(!connected) {
        int err = strlen(PQerrorMessage(conn));
        if(err) {
            status = CONNECTION_BAD;
        }

        if(status == CONNECTION_BAD) {
            //DBG("error %s", PQerrorMessage(conn));
            disconnected_time = time(0);
            connected_time = 0;
            handler->onConnectionFailed(this, PQerrorMessage(conn));
        }
    }
}

bool PGConnection::flush_conn()
{
    if(1==PQflush(conn)) {
        handler->onSock(this, IConnectionHandler::PG_SOCK_RW);
        return true;
    }

    return false;
}

bool PGConnection::reset_conn()
{
    if(!handler) return false;

    if(conn) {
        handler->onSock(this, IConnectionHandler::PG_SOCK_DEL);
        handler->onReset(this, connected);
        PQfinish(conn);
    }
    conn = PQconnectStart(connection_info.c_str());
    if(!conn) {
        ERROR("cann't create pq connection");
        return false;
    }
    if (PQsetnonblocking(conn, 1) == -1) {
        handler->onPQError(this, PQerrorMessage(conn));
        return false;
    }

    conn_fd = PQsocket(conn);
    handler->onSock(this, IConnectionHandler::PG_SOCK_NEW);
    status = CONNECTION_BAD;
    pipe_status = PQ_PIPELINE_OFF;
    connected = false;

    return true;
}

PGconn * PGConnection::get_pg_conn()
{
    return conn;
}

void PGConnection::close_conn()
{
    if(conn) {
        if(connected) handler->onDisconnect(this);
        handler->onSock(this, IConnectionHandler::PG_SOCK_DEL);
        status = CONNECTION_BAD;
        pipe_status = PQ_PIPELINE_OFF;
        connected = false;
        PQfinish(conn);
        conn = 0;
    }
}

bool PGConnection::start_pipe()
{
    if(!conn) return false;
    DBG("connection %p enter in pipeline mode", this);
    return PQenterPipelineMode(conn);
}

bool PGConnection::sync_pipe()
{
    if(!conn) return false;
    return PQpipelineSync(conn);
}

bool PGConnection::exit_pipe()
{
    if(!conn) return false;
    DBG("connection %p live pipeline mode", this);
    return PQexitPipelineMode(conn);
}

bool PGConnection::flush_pipe()
{
    if(pipe_status != PQ_PIPELINE_OFF) {
        PQsendFlushRequest(conn);
    }
    return flush_conn();
}

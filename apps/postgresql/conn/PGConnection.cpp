#include "PGConnection.h"
#include "log.h"
#include "../PostgreSQL.h"
#include "../pg_log.h"

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

    PostgresPollingStatusType poll_status = PQconnectPoll(conn);
    status = PQstatus(conn);
    pipe_status = PQpipelineStatus(conn);

    if(PostgreSQL::instance()->getLogPgEvents())
        DBG(pg_log::print_pg_conn_status(PQdb(conn), status, poll_status, pipe_status).c_str());

    switch((int)poll_status) {
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
            handler->onSock(this, IConnectionHandler::PG_SOCK_DEL);
            handler->onConnectionFailed(this, PQerrorMessage(conn));
        }
    }
}

bool PGConnection::flush_conn()
{
    int ret = PQflush(conn);
    switch(ret) {
    case 0:
        break;
    case 1:
        handler->onSock(this, IConnectionHandler::PG_SOCK_RW);
        return true;
    default: /* -1 */
        ERROR("PQflush(%p): %d. %s", conn, ret, PQerrorMessage(conn));
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
    int ret = PQpipelineSync(conn);
    if(!ret) {
        ERROR("PQpipelineSync: %d. %s", ret, PQerrorMessage(conn));
    }
    return ret;
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

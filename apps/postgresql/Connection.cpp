#include "Connection.h"
#include "Transaction.h"
#include <log.h>
# include <sys/socket.h>
# include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <AmUtils.h>

IPGConnection::~IPGConnection()
{
    if(planned) delete planned;
}

void IPGConnection::check_mode()
{
    if(isBusy()) return;
    if(pipe_status == PQ_PIPELINE_ON && !is_pipeline) exit_pipe();
    else if(pipe_status == PQ_PIPELINE_OFF && is_pipeline) start_pipe();
}

bool IPGConnection::runTransaction(IPGTransaction* trans)
{
    if(cur_transaction)
        return false;
    trans->reset(this);
    cur_transaction = trans;
    check();
    return true;
}

bool IPGConnection::addPlannedTransaction(IPGTransaction* trans)
{
    if(planned) {
        WARN("exist planned transaction, rewrite it");
        delete planned;
    }
    planned = trans;
    return true;
}

void IPGConnection::startPipeline()
{
    is_pipeline = true;
    check_mode();
}

bool IPGConnection::flushPipeline()
{
    if(pipe_status != PQ_PIPELINE_ON) return false;
    return flush_conn();
}

bool IPGConnection::syncPipeline()
{
    if(pipe_status != PQ_PIPELINE_ON) return false;
    return sync_pipe();
}

void IPGConnection::exitPipeline()
{
    is_pipeline = false;
    check_mode();
}

void IPGConnection::check()
{
    if(status != CONNECTION_BAD) {
        check_conn();
    }

    if(status == CONNECTION_OK && cur_transaction) {
        cur_transaction->check();
        if(cur_transaction->get_status() == IPGTransaction::FINISH) {
            //DBG("finish transaction");
            cur_transaction = 0;
            check_mode();
            if(planned) runTransaction(planned);
            planned = 0;
        }
    }
}

bool IPGConnection::reset()
{
    disconnected_time = time(0);
    stopTransaction();
    if(reset_conn()) {
        check_conn();
        return true;
    }
    return false;
}

void IPGConnection::cancelTransaction()
{
    if(cur_transaction && cur_transaction->get_status() != IPGTransaction::FINISH) {
        cur_transaction->cancel();
    }
}

void IPGConnection::stopTransaction()
{
    if(handler && cur_transaction) handler->onStopTransaction(cur_transaction);
    cur_transaction = 0;
    delete planned;
    planned = 0;
}

PGConnection::PGConnection(const std::string& conn_info, IConnectionHandler* handler)
: IPGConnection(conn_info, handler), conn(0), connected(false){}

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
            close_conn();
            disconnected_time = time(0);
            handler->onDisconnect(this);
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
            if(!connected && status == CONNECTION_OK) {
                connected = true;
                //PQtrace(conn, stderr);
                PQsetErrorVerbosity(conn, PQERRORS_VERBOSE);
                handler->onConnect(this);
            }
        case PGRES_POLLING_READING:
            if(connected && cur_transaction) {
                if(flush_conn()) {
                    handler->onSock(this, IConnectionHandler::PG_SOCK_RW);
                }
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
            handler->onConnectionFailed(this, PQerrorMessage(conn));
        }
    }
}

bool PGConnection::flush_conn()
{
    if(pipe_status != PQ_PIPELINE_OFF) {
        PQsendFlushRequest(conn);
    }
    return PQflush(conn);
}

bool PGConnection::reset_conn()
{
    if(!handler) return false;

    if(conn) {
        handler->onSock(this, IConnectionHandler::PG_SOCK_DEL);
        handler->onReset(this);
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

void * PGConnection::get_conn()
{
    return conn;
}

void PGConnection::close_conn()
{
    if(conn) {
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

MockConnection::MockConnection(IConnectionHandler* handler)
: IPGConnection("mock", handler)
{}

MockConnection::~MockConnection()
{
    MockConnection::close_conn();
}

void MockConnection::check_conn()
{
    if(!handler) return;
    
    if(status == CONNECTION_BAD) {
        status = CONNECTION_MADE;
        handler->onSock(this, IConnectionHandler::PG_SOCK_READ);
    } else if(status == CONNECTION_MADE) {
        status = CONNECTION_OK;
        handler->onConnect(this);
    }
}

bool MockConnection::flush_conn()
{
    return true;
}

bool MockConnection::reset_conn()
{
    if(!handler) return false;

    if(conn_fd != -1) {
        handler->onReset(this);
        handler->onSock(this, IConnectionHandler::PG_SOCK_DEL);
        status = CONNECTION_BAD;
        ::close(conn_fd);
        conn_fd = -1;
    }

    conn_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    handler->onSock(this, IConnectionHandler::PG_SOCK_NEW);

    return true;
}

void* MockConnection::get_conn()
{
    return this;
}

void MockConnection::close_conn()
{
    if(conn_fd != -1) {
        handler->onSock(this, IConnectionHandler::PG_SOCK_DEL);
        status = CONNECTION_BAD;
        ::close(conn_fd);
        conn_fd = -1;
    }
}

bool MockConnection::start_pipe()
{
    pipe_status = PQ_PIPELINE_ON;
    return true;
}

bool MockConnection::sync_pipe()
{
    return true;
}

bool MockConnection::exit_pipe()
{
    pipe_status = PQ_PIPELINE_OFF;
    return true;
}

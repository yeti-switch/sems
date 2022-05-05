#include "Connection.h"
#include "Transaction.h"
#include <log.h>
# include <sys/socket.h>
# include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

IPGConnection::~IPGConnection()
{
    if(planned) delete planned;
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

void IPGConnection::check()
{
    if(status != CONNECTION_BAD) {
        check_conn();
    }

    if(status == CONNECTION_OK && cur_transaction) {
        cur_transaction->check();
        if(cur_transaction->get_status() == IPGTransaction::FINISH) {
            cur_transaction = 0;
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
    close_conn();
}

void PGConnection::check_conn()
{
    if(!handler) return;

    if(connected) {
        if(!PQconsumeInput(conn)) {
            PQfinish(conn);
            status = CONNECTION_BAD;
            connected = false;
            conn = 0;
            disconnected_time = time(0);
            handler->onSock(this, IConnectionHandler::PG_SOCK_DEL);
            handler->onDisconnect(this);
            return;
        }
    }

    PostgresPollingStatusType   st = PQconnectPoll(conn);
    status = PQstatus(conn);
    switch((int)st) {
        case PGRES_POLLING_OK:
            if(!connected && status == CONNECTION_OK) {
                connected = true;
                handler->onConnect(this);
            }
        case PGRES_POLLING_READING:
            handler->onSock(this, IConnectionHandler::PG_SOCK_READ);
            break;
        case PGRES_POLLING_WRITING:
            handler->onSock(this, IConnectionHandler::PG_SOCK_WRITE);
            break;
        case PGRES_POLLING_FAILED:
            disconnected_time = time(0);
            handler->onConnectionFailed(this, PQerrorMessage(conn));
            break;
    }
}

bool PGConnection::reset_conn()
{
    if(!handler) return false;

    if(conn) {
        handler->onSock(this, IConnectionHandler::PG_SOCK_DEL);
        handler->onReset(this);
        if(!PQresetStart(conn)) {
            handler->onPQError(this, PQerrorMessage(conn));
            return false;
        }
    } else {
        conn = PQconnectStart(connection_info.c_str());
        if(!conn) {
            ERROR("cann't create pq connection");
            return false;
        }
        if (PQsetnonblocking(conn, 1) == -1) {
            handler->onPQError(this, PQerrorMessage(conn));
            return false;
        }
    }

    conn_fd = PQsocket(conn);
    handler->onSock(this, IConnectionHandler::PG_SOCK_NEW);
    status = CONNECTION_BAD;
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
        connected = false;
        PQfinish(conn);
        conn = 0;
    }
}

MockConnection::MockConnection(IConnectionHandler* handler)
: IPGConnection("mock", handler)
{}

MockConnection::~MockConnection()
{
    close_conn();
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

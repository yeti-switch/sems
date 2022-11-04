#include "MockConnection.h"

# include <sys/socket.h>
# include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>


MockConnection::MockConnection(IConnectionHandler* handler)
  : Connection("mock", "mock", handler)
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

bool MockConnection::flush_conn([[maybe_unused]] bool flush_pipe)
{
    return true;
}

bool MockConnection::reset_conn()
{
    if(!handler) return false;

    if(conn_fd != -1) {
        handler->onReset(this, false);
        handler->onSock(this, IConnectionHandler::PG_SOCK_DEL);
        status = CONNECTION_BAD;
        ::close(conn_fd);
        conn_fd = -1;
    }

    conn_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    handler->onSock(this, IConnectionHandler::PG_SOCK_NEW);

    return true;
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

#include "MockConnection.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/eventfd.h>

MockConnection::MockConnection(IConnectionHandler *handler)
    : Connection("mock", "mock", handler)
    , conn_fd(-1)
{
}

MockConnection::~MockConnection()
{
    MockConnection::close_conn();
}

void MockConnection::check_conn()
{
    if (!handler)
        return;

    if (status == CONNECTION_BAD) {
        status = CONNECTION_MADE;
        handler->onSock(this, IConnectionHandler::PG_SOCK_WRITE);
    } else if (status == CONNECTION_MADE) {
        status = CONNECTION_OK;
        handler->onConnect(this);
        handler->onSock(this, IConnectionHandler::PG_SOCK_READ);
    } else if (status == CONNECTION_OK) {
        int64_t u;
        do {
            u = ::read(conn_fd, &u, sizeof(int64_t));
        } while (u > 0);
    }
}

bool MockConnection::flush_conn()
{
    return true;
}

bool MockConnection::reset_conn()
{
    if (!handler)
        return false;

    if (conn_fd != -1) {
        handler->onReset(this, false);
        handler->onSock(this, IConnectionHandler::PG_SOCK_DEL);
        status = CONNECTION_BAD;
        ::close(conn_fd);
        conn_fd = -1;
    }

    conn_fd = eventfd(0, EFD_NONBLOCK);
    handler->onSock(this, IConnectionHandler::PG_SOCK_NEW);

    return true;
}

void MockConnection::close_conn()
{
    if (conn_fd != -1) {
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
    uint64_t u = 1;
    return write(conn_fd, &u, sizeof(u)) == sizeof(u);
}

bool MockConnection::exit_pipe()
{
    pipe_status = PQ_PIPELINE_OFF;
    return true;
}

bool MockConnection::flush_pipe()
{
    return true;
}

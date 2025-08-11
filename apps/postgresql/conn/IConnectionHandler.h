#pragma once

#include <string>
using std::string;

class Connection;
class Transaction;

struct IConnectionHandler {
    enum EventType {
        PG_SOCK_NEW = 0,
        PG_SOCK_DEL,
        PG_SOCK_WRITE,
        PG_SOCK_READ,
        PG_SOCK_RW,
    };

    virtual ~IConnectionHandler() {}
    virtual void onSock(Connection *conn, EventType type)                  = 0;
    virtual void onConnect(Connection *conn)                               = 0;
    virtual void onConnectionFailed(Connection *conn, const string &error) = 0;
    virtual void onDisconnect(Connection *conn)                            = 0;
    virtual void onReset(Connection *conn, bool connected)                 = 0;
    virtual void onPQError(Connection *conn, const string &error)          = 0;
    virtual void onStopTransaction(Transaction *trans)                     = 0;
};

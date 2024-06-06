#include "AmMediaConnectionsHolder.h"

#define PredicateByConn         [&](auto _conn) { return _conn == conn; }
#define PredicateByConnType     [&](auto conn) { return conn->getConnType() == type; }
#define PredicateByConnTypes    [&](auto conn) {\
                                    for(auto type : types)\
                                        if(conn->getConnType() == type)\
                                            return true;\
                                    \
                                    return false;\
                                }\

AmMediaConnectionsHolder::AmMediaConnectionsHolder()
  : cur_rtp_conn(nullptr),
    cur_rtcp_conn(nullptr),
    cur_udptl_conn(nullptr),
    cur_raw_conn(nullptr)
{
}

AmMediaConnectionsHolder::~AmMediaConnectionsHolder()
{
    removeConnections();
}

void AmMediaConnectionsHolder::addConnection(AmStreamConnection* conn, Completed completed)
{
    addItem(conn, completed);
}

void AmMediaConnectionsHolder::addConnections(const vector<AmStreamConnection*>& conns, Completed completed)
{
    addItems(conns, completed);
}

void AmMediaConnectionsHolder::findConnection(Predicate predicate, Result result)
{
    findItem(predicate, result);
}

void AmMediaConnectionsHolder::findConnection(AmStreamConnection* conn, Result result)
{
    findConnection(PredicateByConn, result);
}

void AmMediaConnectionsHolder::findConnection(AmStreamConnection::ConnectionType type, Result result)
{
    findConnection(PredicateByConnType, result);
}

void AmMediaConnectionsHolder::findCurRtpConn(Result result)
{
    if(cur_rtp_conn)
        findConnection(cur_rtp_conn, result);
}

void AmMediaConnectionsHolder::findCurRtcpConn(Result result)
{
    if(cur_rtcp_conn)
        findConnection(cur_rtcp_conn, result);
}

void AmMediaConnectionsHolder::findCurUdptlConn(Result result)
{
    if(cur_udptl_conn)
        findConnection(cur_udptl_conn, result);
}

void AmMediaConnectionsHolder::findCurRawConn(Result result)
{
    if(cur_raw_conn)
        findConnection(cur_raw_conn, result);
}

void AmMediaConnectionsHolder::findConnections(Predicate predicate, MultipleResult result)
{
    findItems(predicate, result);
}

void AmMediaConnectionsHolder::findConnections(AmStreamConnection::ConnectionType type, MultipleResult result)
{
    findConnections(PredicateByConnType, result);
}

void AmMediaConnectionsHolder::findConnections(const vector<AmStreamConnection::ConnectionType>& types, MultipleResult result)
{
    findConnections(PredicateByConnTypes, result);
}

AmStreamConnection* AmMediaConnectionsHolder::getConnection(Predicate predicate)
{
    AmStreamConnection* res;
    findItem(predicate, [&](auto conn){ res = conn; });
    return res;
}

AmStreamConnection* AmMediaConnectionsHolder::getConnection(AmStreamConnection* conn)
{
    return getConnection(PredicateByConn);
}

AmStreamConnection* AmMediaConnectionsHolder::getConnection(AmStreamConnection::ConnectionType type)
{
    return getConnection(PredicateByConnType);
}

vector<AmStreamConnection*> AmMediaConnectionsHolder::getConnections(Predicate predicate)
{
    vector<AmStreamConnection*> res;
    findItems(predicate, [&](auto conns){
        res.insert(res.end(), conns.begin(), conns.end());
    });
    return res;
}

vector<AmStreamConnection*> AmMediaConnectionsHolder::getConnections(AmStreamConnection::ConnectionType type)
{
    return getConnections(PredicateByConnType);
}

vector<AmStreamConnection*> AmMediaConnectionsHolder::getConnections(const vector<AmStreamConnection::ConnectionType>& types)
{
    return getConnections(PredicateByConnTypes);
}

void AmMediaConnectionsHolder::removeConnection(Predicate predicate, Completed completed)
{
    removeItem(predicate, completed);
}

void AmMediaConnectionsHolder::removeConnection(AmStreamConnection* conn, Completed completed)
{
    removeConnection(PredicateByConn, completed);
}

void AmMediaConnectionsHolder::removeCurRtpConn()
{
    if(cur_rtp_conn)
        removeConnection(cur_rtp_conn, [&]() { this->setCurRtpConn(nullptr); });
}

void AmMediaConnectionsHolder::removeCurRtcpConn()
{
    if(cur_rtcp_conn)
        removeConnection(cur_rtcp_conn, [&]() { this->setCurRtcpConn(nullptr); });
}

void AmMediaConnectionsHolder::removeCurUdptlConn()
{
    if(cur_udptl_conn)
        removeConnection(cur_udptl_conn, [&]() { this->setCurUdptlConn(nullptr); });
}

void AmMediaConnectionsHolder::removeCurRawConn()
{
    if(cur_raw_conn)
        removeConnection(cur_raw_conn, [&]() { this->setCurRawConn(nullptr); });
}

void AmMediaConnectionsHolder::removeConnections(Completed completed)
{
    removeItems(completed);
}

void AmMediaConnectionsHolder::removeConnections(Predicate predicate, Completed completed)
{
    removeItems(predicate, completed);
}

void AmMediaConnectionsHolder::removeConnections(AmStreamConnection::ConnectionType type, Completed completed)
{
    removeConnections(PredicateByConnType, completed);
}

void AmMediaConnectionsHolder::removeConnections(const vector<AmStreamConnection::ConnectionType>& types, Completed completed)
{
    removeConnections(PredicateByConnTypes, completed);
}

void AmMediaConnectionsHolder::iterateConnections(Iterator iterator, Completed completed)
{
    iterateItems(iterator, completed);
}

void AmMediaConnectionsHolder::iterateConnections(Predicate predicate, Iterator iterator, Completed completed)
{
    iterateItems(predicate, iterator, completed);
}

void AmMediaConnectionsHolder::iterateConnections(AmStreamConnection::ConnectionType type, Iterator iterator, Completed completed)
{
    iterateConnections(PredicateByConnType, iterator, completed);
}

void AmMediaConnectionsHolder::iterateConnections(const vector<AmStreamConnection::ConnectionType>& types, Iterator iterator, Completed completed)
{
    iterateConnections(PredicateByConnTypes, iterator, completed);
}

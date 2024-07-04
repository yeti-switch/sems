#pragma once

#include "AmArg.h"
#include "AmConcurrentVector.h"
#include "AmRtpConnection.h"

class AmMediaConnectionsHolder
  : public AmObject,
    protected AmConcurrentVector<AmStreamConnection*>
{
private:
    AmStreamConnection* cur_rtp_conn;
    AmStreamConnection* cur_rtcp_conn;
    AmStreamConnection* cur_udptl_conn;
    AmStreamConnection* cur_raw_conn;

public:
    AmMediaConnectionsHolder();
    virtual ~AmMediaConnectionsHolder();

    typedef function<bool(AmStreamConnection* conn)> Predicate;
    typedef function<void(AmStreamConnection* conn)> Result;
    typedef function<void(vector<AmStreamConnection*> conns)> MultipleResult;
    typedef function<void(AmStreamConnection* conn, bool& stop)> Iterator;
    typedef function<void()> Completed;

    void setCurRtpConn(AmStreamConnection* conn) { cur_rtp_conn = conn; }
    void setCurRtcpConn(AmStreamConnection* conn) { cur_rtcp_conn = conn; }
    void setCurUdptlConn(AmStreamConnection* conn) { cur_udptl_conn = conn; }
    void setCurRawConn(AmStreamConnection* conn) { cur_raw_conn = conn; }

    AmStreamConnection* getCurRtpConn() { return cur_rtp_conn; }
    AmStreamConnection* getCurRtcpConn() { return cur_rtcp_conn; }
    AmStreamConnection* getCurUdptlConn() { return cur_udptl_conn; }
    AmStreamConnection* getCurRawConn() { return cur_raw_conn; }

    void addConnection(AmStreamConnection* conn, Completed completed = nullptr);
    void addConnections(const vector<AmStreamConnection*>& conns, Completed completed = nullptr);

    void findConnection(Predicate predicate, Result result);
    void findConnection(AmStreamConnection* conn, Result result);
    void findConnection(AmStreamConnection::ConnectionType type, Result result);

    void findCurRtpConn(Result result);
    void findCurRtcpConn(Result result);
    void findCurUdptlConn(Result result);
    void findCurRawConn(Result result);

    void findConnections(Predicate predicate, MultipleResult result);
    void findConnections(AmStreamConnection::ConnectionType type, MultipleResult result);
    void findConnections(const vector<AmStreamConnection::ConnectionType>& types, MultipleResult result);

    AmStreamConnection* getConnection(Predicate predicate);
    AmStreamConnection* getConnection(AmStreamConnection* conn);
    AmStreamConnection* getConnection(AmStreamConnection::ConnectionType type);

    vector<AmStreamConnection*> getConnections(Predicate predicate);
    vector<AmStreamConnection*> getConnections(AmStreamConnection::ConnectionType type);
    vector<AmStreamConnection*> getConnections(const vector<AmStreamConnection::ConnectionType>& types);

    void removeConnection(Predicate predicate, Completed completed = nullptr);
    void removeConnection(AmStreamConnection* conn, Completed completed = nullptr);

    void removeCurRtpConn();
    void removeCurRtcpConn();
    void removeCurUdptlConn();
    void removeCurRawConn();

    void removeConnections(Completed completed = nullptr);
    void removeConnections(Predicate predicate, Completed completed = nullptr);
    void removeConnections(AmStreamConnection::ConnectionType type, Completed completed = nullptr);
    void removeConnections(const vector<AmStreamConnection::ConnectionType>& types, Completed completed = nullptr);

    void iterateConnections(Iterator iterator, Completed completed = nullptr);
    void iterateConnections(Predicate predicate, Iterator iterator, Completed completed = nullptr);
    void iterateConnections(AmStreamConnection::ConnectionType type, Iterator iterator, Completed completed = nullptr);
    void iterateConnections(const vector<AmStreamConnection::ConnectionType>& types, Iterator iterator, Completed completed = nullptr);
};

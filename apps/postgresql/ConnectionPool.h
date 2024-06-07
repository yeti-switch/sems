#pragma once

#include <chrono>
#include <string>
#include <vector>
#include <list>
using std::string;
using std::vector;
using std::list;

#include <PostgreSqlAPI.h>
#include "conn/Connection.h"
#include "trans/Transaction.h"

class PoolWorker;

extern const string pool_type_master;
extern const string pool_type_slave;

class ConnectionPool
{
    vector<Connection*> connections;
    unsigned int cur_conn;
    PoolWorker* worker;
    PGPool pool;
    PGWorkerPoolCreate::PoolType type;
    AtomicCounter& connected;
    AtomicCounter& poolsize;
public:
    ConnectionPool(const PGPool& pool, PoolWorker* worker, PGWorkerPoolCreate::PoolType type);
    ~ConnectionPool();

    bool processEvent(void* p);
    Connection* getFreeConnection();
    Connection* getConnection(int fd);
    vector<Connection*> getLifetimeOverConnections(time_t& nextTime);
    bool checkConnection(Connection* conn, bool connect);
    void runTransactionForPool(Transaction* trans);
    void resetConnections();
    void usePipeline(bool is_pipeline);

    void getStats(AmArg& stats, uint32_t conn_lifetime);
    const PGPool& getInfo() { return pool; }
};

#include "ConnectionPool.h"
#include "PostgreSQL.h"
#include "PoolWorker.h"
#include "pqtypes-int.h"

#include <stdio.h>
#include <sstream>

#include <AmSessionContainer.h>
#include <AmStatistics.h>

const string pool_type_master("master");
const string pool_type_slave("slave");

ConnectionPool::ConnectionPool(const PGPool& pool, PoolWorker* worker, PGWorkerPoolCreate::PoolType type)
  : worker(worker), pool(pool), type(type),
    connected(stat_group(Gauge, MOD_NAME, "pool_connected").addAtomicCounter()
        .addLabel("worker", worker->get_name())
        .addLabel("type", type == PGWorkerPoolCreate::Master ? pool_type_master : pool_type_slave)),
    poolsize(stat_group(Gauge, MOD_NAME, "pool_size").addAtomicCounter()
          .addLabel("worker", worker->get_name())
          .addLabel("type", type == PGWorkerPoolCreate::Master ? pool_type_master : pool_type_slave))
{
    std::stringstream conn_info, conn_log_info;

    conn_info << "host=" << pool.host;
    conn_info << " port=" << pool.port;
    conn_info << " dbname=" << pool.name;
    conn_info << " user=" << pool.user;
    conn_info << " password=" << pool.pass;

    conn_log_info << pool.host << ":" << pool.port << "/" << pool.name;

    for(int i = 0; i < pool.pool_size; i++) {
        connections.push_back(PolicyFactory::instance()->createConnection(
            conn_info.str(), conn_log_info.str(), worker));
        connections.back()->reset();
    }

    poolsize.set(pool.pool_size);
}

ConnectionPool::~ConnectionPool()
{
    auto connections_copy = connections;
    connections.clear();
    for(auto& conn : connections_copy) delete conn;
}

Connection * ConnectionPool::getFreeConnection()
{
    for(auto& conn : connections) {
        if(!conn->isBusy() && conn->getStatus() == CONNECTION_OK) return conn;
    }
    return 0;
}

Connection * ConnectionPool::getConnection(int fd)
{
    for(auto& conn : connections) {
        if(fd == conn->getSocket()) return conn;
    }
    return 0;
}

vector<Connection*> ConnectionPool::getLifetimeOverConnections(time_t& nextTime)
{
    vector<Connection*> conns;
    time_t current = time(0);
    for(auto& conn : connections) {
        if(conn->getConnectedTime() &&
           current > conn->getConnectedTime()) {
           if(!conn->getCurrentTransaction())
                conns.push_back(conn);
        } else if(!nextTime || nextTime > conn->getConnectedTime())
            nextTime = conn->getConnectedTime();
    }
    return conns;
}

bool ConnectionPool::checkConnection(Connection* conn, bool connect)
{
    for(auto& conn_ : connections) {
        if(conn_ == conn) {
            connect ? connected.inc() : connected.dec();
            return true;
        }
    }
    return false;
}

void ConnectionPool::runTransactionForPool(Transaction* trans)
{
    for(auto& conn : connections) {
        if(conn->getStatus() == CONNECTION_OK) {
            if(!conn->isBusy())
                conn->runTransaction(trans->clone());
            else
                conn->addPlannedTransaction(trans->clone());
        }
    }
}

void ConnectionPool::resetConnections()
{
    for(auto& conn : connections) {
        conn->reset();
    }
}

void ConnectionPool::usePipeline(bool is_pipeline)
{
    for(auto& conn : connections) {
        if(is_pipeline)
            conn->startPipeline();
        else
            conn->exitPipeline();
    }
}

void ConnectionPool::getStats(AmArg& stats, uint32_t conn_lifetime)
{
    auto now = time(0);

    AmArg &pool_stats = (type==PGWorkerPoolCreate::Master) ?
        stats[pool_type_master] : stats[pool_type_slave];

    pool_stats["connected"] = (long long)connected.get();
    AmArg &conns = pool_stats["connections"];

    for(auto& conn : connections) {
        conns.push(AmArg());
        auto &conn_info = conns.back();
        conn_info["status"] = conn->getStatus();
        conn_info["pipe_status"] = conn->getPipeStatus();
        conn_info["socket"] = conn->getSocket();
        conn_info["busy"] = conn->isBusy();
        conn_info["queries_finished"] = conn->getQueriesFinished();

        if(conn->getStatus() == CONNECTION_OK) {
            auto uptime = now - conn->getConnectedTime();
            conn_info["uptime"] = uptime;
            if(conn_lifetime) {
                conn_info["ttl"] = conn_lifetime - uptime;
            }
        }

        if(conn->getCurrentTransaction()) {
            conn_info["tr_status"] = conn->getCurrentTransaction()->get_status();
            conn_info["tr_db_state"] = conn->getCurrentTransaction()->get_state();
            conn_info["tr_size"] = conn->getCurrentTransaction()->get_size();
        }
    }

}

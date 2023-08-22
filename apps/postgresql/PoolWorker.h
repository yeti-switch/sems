#pragma once

#include <ampi/PostgreSqlAPI.h>

#include "ConnectionPool.h"

#include <chrono>
#include <string>
#include <vector>
#include <set>
#include <list>

using std::string;
using std::vector;
using std::set;
using std::list;

class pending_reset_time_less
{
public:
  bool operator()(Connection* const a, Connection* const b) const
  {
      if(a->getPendingResetTime() <  b->getPendingResetTime()) return true;
      return a < b;
  }
};

class PoolWorker
  : public ITransactionHandler,
    public IConnectionHandler
{
    int epoll_fd;
    string name;

    bool failover_to_slave;
    bool retransmit_enable;
    bool use_pipeline;
    uint32_t retransmit_interval;
    uint32_t reconnect_interval;
    uint32_t trans_wait_time;
    uint32_t batch_timeout;
    uint32_t batch_size;
    uint32_t max_queue_length;
    uint32_t conn_lifetime;

    AmTimerFd workTimer;

    ConnectionPool* master;
    ConnectionPool* slave;

    struct resetConnectionsContainer
      : public set<Connection*, pending_reset_time_less>
    {
        time_t getNearestResetTime() {
            return (*begin())->getPendingResetTime();
        }
    } resetConnections;

    struct TransContainer
    {
        Transaction* trans;
        ConnectionPool* currentPool;
        time_t createdTime;
        std::chrono::steady_clock::time_point sendTime;
        string token;
        string sender_id;
        TransContainer(Transaction* trans, ConnectionPool* pool,
                       const string& sender, const string& token)
            : trans(trans), currentPool(pool), createdTime(time(0))
            , token(token), sender_id(sender) {}
    };

    AtomicCounter& tr_size;
    AtomicCounter& finished;
    AtomicCounter& queue_size;
    AtomicCounter& ret_size;
    AtomicCounter& dropped;
    AtomicCounter& finished_time;
    AtomicCounter& canceled;
    AtomicCounter& failed;

    list<TransContainer> transactions;    //active transactions

    map<string,PGPrepareData> prepareds;  //prepared transaction for all connections that has connected
    vector<string> search_pathes;         //search pathes for all connections that has connected
    vector< std::unique_ptr<IQuery> > init_queries; //queries to run on connect
    vector<string> reconnect_errors;

    list<TransContainer> retransmit_q;    //queue of retransmit transactions
    list<TransContainer> queue;           //queue of transaction
    vector<Transaction*> erased;       //temp container for finished transactions(on the next iteration they will be deleted)
    time_t retransmit_next_time;
    time_t wait_next_time;
    time_t reset_next_time;
    time_t send_next_time;
    time_t reconn_next_time;
    time_t minimal_timer_time;
    bool timer_is_set;

    void getFreeConnection(Connection **conn, ConnectionPool **pool, std::function<void(const string&)> func);
    void checkQueue();
    int retransmitTransaction(TransContainer& trans);
    void setWorkTimer(bool immediately);
    void scheduleConnectionReset(Connection *conn, time_t pending_reset_time = time(0));
  public:
    PoolWorker(const string& name, int epollfd);
    ~PoolWorker();

    bool processEvent(void* p);

    void createPool(PGWorkerPoolCreate::PoolType type, const PGPool& pool);

    void runPrepared(const PGPrepareData& prepared);
    void runInitial(IQuery *query);
    void setSearchPath(const vector<string>& search_path);
    void setReconnectErrors(const vector<string>& errors);

    void runTransaction(Transaction* trans, const string& sender_id, const string& token);
    void configure(const PGWorkerConfig& e);
    void resetPools(PGWorkerPoolCreate::PoolType type);
    void resetConnection(int fd);
    void resetPools();

    void onFireTransaction(const TransContainer& trans);
    void onErrorTransaction(const TransContainer& trans, const string& error);
    void applyTimer();
    void onTimer();

    //IConnectionHandler
    void onSock(Connection* conn, EventType type) override;
    void onConnect(Connection* conn) override;
    void onConnectionFailed(Connection* conn, const string& error) override;
    void onDisconnect(Connection* conn) override;
    void onReset(Connection* conn, bool connected) override;
    void onPQError(Connection* conn, const string& error) override;
    void onStopTransaction(Transaction* trans) override;

    //ITransactionHandler
    void onCancel(Transaction* conn) override;
    void onSend(Transaction* conn) override;
    void onError(Transaction* trans, const string& error) override;
    void onErrorCode(Transaction* trans, const string& error) override;
    void onPQError(Transaction* trans, const string& error) override;
    void onFinish(Transaction* trans, const AmArg& result) override;
    void onTuple(Transaction* trans, const AmArg& result) override;

    uint64_t getActiveTasksCount();
    void getStats(AmArg& ret);
    void getConfig(AmArg& ret);
#ifdef TRANS_LOG_ENABLE
    bool getConnectionLog(const AmArg& args);
#endif

    string get_name() { return name; }
};

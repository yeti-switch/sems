#include "PoolWorker.h"

#include "AmUtils.h"
#include <AmSessionContainer.h>
#include <AmStatistics.h>

#include "PostgreSQL.h"
#include "pqtypes-int.h"

#include "trans/NonTransaction.h"
#include "trans/DbTransaction.h"
#include "trans/PreparedTransaction.h"
#include "trans/ConfigTransaction.h"

#include "query/QueryChain.h"

#define ERROR_CALLBACK \
[token, sender_id](const string& error) {\
    if(!sender_id.empty())\
        AmSessionContainer::instance()->postEvent(sender_id, new PGResponseError(error, token));\
}

PoolWorker::PoolWorker(const std::string& name, int epollfd)
  : epoll_fd(epollfd),
    name(name),
    failover_to_slave(false),
    retransmit_enable(false),
    use_pipeline(false),
    retransmit_interval(PG_DEFAULT_RET_INTERVAL),
    reconnect_interval(PG_DEFAULT_REC_INTERVAL),
    trans_wait_time(PG_DEFAULT_WAIT_TIME),
    batch_timeout(PG_DEFAULT_BATCH_TIMEOUT),
    batch_size(PG_DEFAULT_BATCH_SIZE),
    max_queue_length(PG_DEFAULT_MAX_Q_LEN),
    master(0), slave(0),
    tr_size(stat_group(Gauge, MOD_NAME, "queries_active").addAtomicCounter().addLabel("worker", name)),
    finished(stat_group(Counter, MOD_NAME, "queries_finished").addAtomicCounter().addLabel("worker", name)),
    queue_size(stat_group(Gauge, MOD_NAME, "queries_queue_size").addAtomicCounter().addLabel("worker", name)),
    ret_size(stat_group(Gauge, MOD_NAME, "queries_retry_queue_size").addAtomicCounter().addLabel("worker", name)),
    dropped(stat_group(Counter, MOD_NAME, "queries_dropped").addAtomicCounter().addLabel("worker", name)),
    finished_time(stat_group(Counter, MOD_NAME, "queries_finished_time").addAtomicCounter().addLabel("worker", name)),
    canceled(stat_group(Counter, MOD_NAME, "queries_canceled").addAtomicCounter().addLabel("worker", name)),
    failed(stat_group(Counter, MOD_NAME, "queries_failed").addAtomicCounter().addLabel("worker", name)),
    retransmit_next_time(0), wait_next_time(0),
    reset_next_time(0), send_next_time(0),
    reconn_next_time(0), minimal_timer_time(0),
    timer_is_set(false)
{
}

PoolWorker::~PoolWorker()
{
    workTimer.unlink(epoll_fd);
    resetConnections.clear();
    for(auto& trans: transactions) delete trans.trans;
    transactions.clear();
    for(auto& trans: queue) delete trans.trans;
    queue.clear();
    for(auto& trans: retransmit_q) delete trans.trans;
    retransmit_q.clear();
    for(auto& tr : erased) delete tr;
    erased.clear();

    ConnectionPool* destroyed = 0;
    if(master) {
        destroyed = master;
        master = 0;
        delete destroyed;
    }

    if(slave) {
        destroyed = slave;
        slave = 0;
        delete destroyed;
    }
}

void PoolWorker::init()
{
    workTimer.link(epoll_fd, true);
}

uint64_t PoolWorker::getActiveTasksCount()
{
    return
        queue_size.get() +  //queue
        ret_size.get() +    //retransmit
        tr_size.get();      //active
}

void PoolWorker::getConfig(AmArg& ret)
{
    ret["max_queue_length"] = max_queue_length;
    ret["batch_size"] = batch_size;
    ret["batch_timeout"] = batch_timeout;
    ret["trans_wait_time"] = trans_wait_time;
    ret["reconnect_interval"] = reconnect_interval;
    ret["retransmit_interval"] = retransmit_interval;
    ret["retransmit_enable"] = retransmit_enable;
    ret["failover_to_slave"] = failover_to_slave;
    ret["use_pipeline"] = use_pipeline;
    ret["connection_lifetime"] = conn_lifetime;
}

void PoolWorker::getStats(AmArg& ret)
{
    ret["queue"] = (long long)queue_size.get();
    ret["retransmit"] = (long long)ret_size.get();
    ret["dropped"] = (long long)dropped.get();
    ret["active"] = (long long)tr_size.get();
    ret["finished"] = (long long)finished.get();
    ret["canceled"] = (long long)canceled.get();
    ret["failed"] = (long long)failed.get();

    if(master)
        master->getStats(ret, conn_lifetime);
    if(slave)
        slave->getStats(ret, conn_lifetime);
}

#ifdef TRANS_LOG_ENABLE
bool PoolWorker::getConnectionLog(const AmArg& args)
{
    int fd = 0;
    if(isArgInt(args[0]))
        fd = args[0].asInt();
    else if(isArgCStr(args[0]))
        str2int(args[0].asCStr(), fd);
    Connection* conn = 0;
    if(master) conn = master->getConnection(fd);
    if(!conn && slave) conn = master->getConnection(fd);

    if(!conn) return false;

    Transaction* trans = conn->getCurrentTransaction();
    if(!trans) return false;

    return trans->saveLog();
}
#endif

void PoolWorker::onConnect(Connection* conn) {
    INFO("connection %s:%p/%s success", name.c_str(), conn, conn->getConnInfo().c_str());
    if(master && !master->checkConnection(conn, true) && slave) slave->checkConnection(conn, true);
    time_t now = time(0);
    if(conn_lifetime && (reconn_next_time > now + conn_lifetime || !reconn_next_time)) reconn_next_time = now + conn_lifetime;
    if(use_pipeline)
        conn->startPipeline();
    if(!prepareds.empty() || !search_pathes.empty() || !init_queries.empty()) {
        Transaction* trans = new ConfigTransaction(prepareds, search_pathes, init_queries, this);
        if(!conn->runTransaction(trans)) {
            ERROR("connection %p/%s of worker \'%s\' transaction already exists ",
                  conn, conn->getConnInfo().c_str(), name.c_str());
            delete trans;
        }
        if(conn_lifetime) setWorkTimer(false);
    }
    else
        setWorkTimer(true);
}
void PoolWorker::onReset(Connection* conn, bool connected) {
    INFO("pg connection %s:%p/%s reset", name.c_str(), conn, conn->getConnInfo().c_str());
    if(connected && master && !master->checkConnection(conn, false) && slave) slave->checkConnection(conn, false); 
}
void PoolWorker::onPQError(Connection* conn, const std::string& error) {
    ERROR("pg connection %s:%p/%s error: %s", name.c_str(), conn, conn->getConnInfo().c_str(), error.c_str());
}

void PoolWorker::onStopTransaction(Transaction* trans)
{
    ERROR("pg connection %s:%p/%s stopped transaction %d %s",
          name.c_str(),
          trans->get_conn(), trans->get_conn()->getConnInfo().c_str(),
          trans->get_size(), trans->get_query()->get_query().c_str());
    for(auto tr_it = transactions.begin();
        tr_it != transactions.end(); tr_it++) {
        if(trans == tr_it->trans) {
            retransmit_q.emplace_back(tr_it->trans, (ConnectionPool*)0, tr_it->sender_id, tr_it->token);
            tr_size.dec((long long)tr_it->trans->get_size());
            ret_size.inc((long long)tr_it->trans->get_size());
            failed.inc((long long)tr_it->trans->get_size());
            transactions.erase(tr_it);
            return;
        }
    }
}

void PoolWorker::onConnectionFailed(Connection* conn, const std::string& error) {
    ERROR("pg connection %s:%p/%s failed: %s", name.c_str(), conn, conn->getConnInfo().c_str(), error.c_str());
    scheduleConnectionReset(conn, conn->getDisconnectedTime() + reconnect_interval);
}

void PoolWorker::onDisconnect(Connection* conn) {
    INFO("pg connection %s:%p/%s disconnect", name.c_str(), conn, conn->getConnInfo().c_str());
    if(master && !master->checkConnection(conn, false) && slave) slave->checkConnection(conn, false); 
    scheduleConnectionReset(conn);
}

void PoolWorker::onSock(Connection* conn, IConnectionHandler::EventType type)
{
    int ret, conn_fd = conn->getSocket();
    if(conn_fd < 0) {
        return;
    }

    ret = 0;
    if(type == PG_SOCK_NEW) {
        epoll_event event;
        event.events = EPOLLIN | EPOLLERR;
        event.data.ptr = conn;

        // add the socket to the epoll file descriptors
        ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_fd, &event);
    } else if(type == PG_SOCK_DEL) {
        ret = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn_fd, nullptr);
    } else {
        epoll_event event;
        event.events = EPOLLERR;
        event.data.ptr = conn;
        if(type == PG_SOCK_WRITE) event.events |= EPOLLOUT;
        if(type == PG_SOCK_READ) event.events |= EPOLLIN;
        if(type == PG_SOCK_RW) event.events |= EPOLLOUT | EPOLLIN;

        ret = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn_fd, &event);
    }

    if(ret < 0) {
        ERROR("epoll error. reset connection %p", conn);
        scheduleConnectionReset(conn);
    }
}

void PoolWorker::onError(Transaction* trans, const string& error) {
    ERROR("Error of transaction \'%p/%s\' : %s", trans, trans->get_query()->get_query().c_str(), error.c_str());
    for(auto tr_it = transactions.begin();
        tr_it != transactions.end(); tr_it++) {
        if(trans == tr_it->trans) {
            tr_size.dec((long long)tr_it->trans->get_size());
            onErrorTransaction(*tr_it, error);
            transactions.erase(tr_it);
            return;
        }
    }
}


void PoolWorker::onErrorCode(Transaction* trans, const string& error) {
    ERROR("error code: \"%s\"", error.c_str());
    if(reconnect_errors.empty() ||
       reconnect_errors.end() != std::find(reconnect_errors.begin(), reconnect_errors.end(), error))
    {
        scheduleConnectionReset(trans->get_conn(), time(0) + reconnect_interval);
        return;
    }
}

void PoolWorker::onTuple(Transaction* trans, const AmArg& result) {
}

void PoolWorker::onFinish(Transaction* trans, const AmArg& result) {
    setWorkTimer(true);
    erased.push_back(trans);
    //DBG("transaction query \'%p/%s\' finished", trans, trans->get_query()->get_query().c_str());
    for(auto tr_it = transactions.begin();
        tr_it != transactions.end(); tr_it++){
        if(trans == tr_it->trans) {
            /*DBG("post PGResponse %s/%s: %s",
                tr_it->sender_id.data(),
                tr_it->token.data(),
                AmArg::print(result).c_str());*/

            if(!tr_it->sender_id.empty()) {
                AmSessionContainer::instance()->postEvent(
                    tr_it->sender_id, new PGResponse(result, tr_it->token));
            }
            finished.inc((long long)tr_it->trans->get_size());
            tr_size.dec((long long)tr_it->trans->get_size());
            finished_time.inc(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - tr_it->sendTime).count());
            transactions.erase(tr_it);
            return;
        }
    }
}

void PoolWorker::onPQError(Transaction* trans, const std::string& error) {

    DBG("Error of transaction \'%s\' : %s", trans->get_query()->get_query().c_str(), error.c_str());
    scheduleConnectionReset(trans->get_conn());
}

void PoolWorker::onCancel(Transaction* trans) {
    //DBG("transaction with query %s canceling", conn->get_query()->get_query().c_str());
}

void PoolWorker::onSend(Transaction* trans)
{
    for(auto tr_it = transactions.begin();
        tr_it != transactions.end(); tr_it++) {
        if(trans == tr_it->trans) {
            if(!tr_it->sendTime.time_since_epoch().count()) {
                tr_it->sendTime = std::chrono::steady_clock::now();
            }
            return;
        }
    }
}

bool PoolWorker::processEvent(void* p)
{
    if(p == &workTimer) {
        onTimer();
        workTimer.read();
        return true;
    }
    if(master && master->processEvent(p)) return true;
    if(slave && slave->processEvent(p)) return true;
    return false;
}

void PoolWorker::createPool(PGWorkerPoolCreate::PoolType type, const PGPool& pool)
{
    if(type == PGWorkerPoolCreate::Master) {
        if(!master) master = new ConnectionPool(pool, this,  PGWorkerPoolCreate::Master);
        else ERROR("master connection pool of worker %s already created", name.c_str());
    }
    if(type == PGWorkerPoolCreate::Slave) {
        if(!slave) slave = new ConnectionPool(pool, this, PGWorkerPoolCreate::Slave);
        else ERROR("slave connection pool of worker %s already created", name.c_str());
    }
}

void PoolWorker::getFreeConnection(Connection **conn, ConnectionPool **pool, std::function<void(const string&)> func)
{
    do {
        if(!*pool && master)
            *pool = master;
        else if(slave && (!*pool ||
                         *pool == master))
            *pool = slave;
        else {
            func("worker not found");
            return;
        }

        *conn = (*pool)->getFreeConnection();
        if(!*conn) {
            continue;
        }
    } while(!*pool);
}

// -1 - no free connection, wait and break from queue circle
//  0 - transaction has executed or deleted, delete from queue
//  1 - no free connection in slave pool or retransmit time not expired,
//      drop transaction to next timer
int PoolWorker::retransmitTransaction(TransContainer& trans)
{
    retransmit_next_time = 0;
    bool is_ret_timer_set = false;
    time_t current_time = time(0);
    if(!trans.currentPool) {
        Connection* conn = 0;
        ConnectionPool* pool = 0;
        string sender_id = trans.sender_id;
        string token = trans.token;
        getFreeConnection(&conn, &pool, ERROR_CALLBACK);
        if(!conn) return -1;
        transactions.emplace_back(trans.trans, pool, sender_id, token);
        tr_size.inc((long long)trans.trans->get_size());
        wait_next_time = transactions.front().createdTime + trans_wait_time;
        //DBG("worker \'%s\' set next wait time %lu", name.c_str(), wait_next_time);
        conn->runTransaction(trans.trans);
        setWorkTimer(false);
        return 0;
    } else if(trans.currentPool == master){
        if(!failover_to_slave && !retransmit_enable) {
            if (trans.trans != NULL) {
                delete trans.trans;
                trans.trans = NULL;
            }
            return 0;
        } else if(current_time - trans.createdTime < retransmit_interval) {
            if(!is_ret_timer_set) {
                retransmit_next_time = trans.createdTime + retransmit_interval;
                is_ret_timer_set = true;
                //DBG("worker \'%s\' set next retransmit time: %lu", name.c_str(), retransmit_next_time);
            }
            return 1;
        }
        Connection* conn = 0;
        ConnectionPool* pool = master;
        string sender_id = "";
        string token = trans.token;
        getFreeConnection(&conn, &pool, ERROR_CALLBACK);
        if(failover_to_slave && slave && !conn)
            return 1;
        else if(failover_to_slave && conn) {
            transactions.emplace_back(trans.trans, pool, trans.sender_id, token);
            tr_size.inc((long long)trans.trans->get_size());
            wait_next_time = transactions.front().createdTime + trans_wait_time;
            //DBG("worker \'%s\' set next wait time %lu", name.c_str(), wait_next_time);
            setWorkTimer(false);
            conn->runTransaction(trans.trans);
            return 0;
        } else if((failover_to_slave && !slave) ||
                  !failover_to_slave) {
            if(!retransmit_enable) {
                if (trans.trans != NULL) {
                    delete trans.trans;
                    trans.trans = NULL;
                }
                return 0;
            } else {
                trans.currentPool = 0;
                return retransmitTransaction(trans);
            }
        }
    } if(!retransmit_enable) {
        if (trans.trans != NULL) {
            delete trans.trans;
            trans.trans = NULL;
        }

        return 0;
    } else if(current_time - trans.createdTime < retransmit_interval) {
        if(!is_ret_timer_set) {
            retransmit_next_time = trans.createdTime + retransmit_interval;
            is_ret_timer_set = true;
            //DBG("worker \'%s\' set next retransmit time: %lu", name.c_str(), retransmit_next_time);
        }
        return 1;
    }

    trans.currentPool = 0;
    return retransmitTransaction(trans);
}

void PoolWorker::setWorkTimer(bool immediately)
{
    if(immediately) {
        minimal_timer_time = 1;
        timer_is_set = false;
        //DBG("set timer immediately");
    } else {
        time_t current = time(0);
        time_t interval = minimal_timer_time/1000000;

        auto update_timer_interval = [&interval, current](time_t next_time)
        {
            if(next_time &&
               (!interval || next_time < current || next_time - current < interval))
            {
                interval = next_time - current > 0 ? next_time - current : 1;
            }
        };

        update_timer_interval(reset_next_time);
        update_timer_interval(retransmit_next_time);
        update_timer_interval(wait_next_time);
        update_timer_interval(send_next_time);
        update_timer_interval(reconn_next_time);

        if(!minimal_timer_time || interval*1000000 < minimal_timer_time) {
            minimal_timer_time = interval*1000000;
            timer_is_set = false;
        }
        //DBG("set timer %lu, %lu", interval, minimal_timer_time);
    }
    //DBG("worker \'%s\'\n\t\tcurrent_time - %lu, reset_next_time - %lu, retransmit_next_time - %lu, wait_next_time - %lu, send_next_time - %lu, reconn_next_time - %lu",
    //    get_name().c_str(), time(0), reset_next_time, retransmit_next_time, wait_next_time, send_next_time, reconn_next_time);
}

void PoolWorker::scheduleConnectionReset(Connection *conn, time_t pending_reset_time)
{
    conn->setPendingResetTime(pending_reset_time);
    resetConnections.insert(conn);
    reset_next_time = resetConnections.getNearestResetTime();
    setWorkTimer(false);
}

void PoolWorker::checkQueue()
{
    for(auto trans_it = retransmit_q.begin();
        trans_it != retransmit_q.end();) {
        int tr_size = trans_it->trans->get_size();
        int ret = retransmitTransaction(*trans_it);
        if(ret < 0) break;
        else if(ret > 0) trans_it++;
        else {
            ret_size.dec((long long)tr_size);
            trans_it = retransmit_q.erase(trans_it);
        }
    }

    if(send_next_time > time(0) && queue.size() < batch_size) return;

    Transaction* trans = 0;
    size_t count = 0;
    bool need_send = false;
    for(auto trans_it = queue.begin();
        trans_it != queue.end();) {
        if(!trans) {
            trans = trans_it->trans->clone();
            count += trans_it->trans->get_size();
        } else if(!trans->merge(trans_it->trans)) {
            need_send = true;
            trans_it--;
        } else {
            count += trans_it->trans->get_size();
        }

        auto next_it = trans_it; next_it++;
        if(count >= batch_size || need_send || next_it == queue.end()) {
            TransContainer tr(trans, (ConnectionPool*)0, trans_it->sender_id, trans_it->token);
            int ret = retransmitTransaction(tr);
            if(ret < 0) {
                delete trans;
                trans = NULL;
                break;
            } else {
                for(auto it = queue.begin(); it != next_it; it++) {
                    delete it->trans;
                    it->trans = NULL;
                }
                trans_it = queue.erase(queue.begin(), next_it);
                queue_size.dec(count);
            }
            count = 0;
            need_send = false;
            trans = 0;
        } else {
            trans_it++;
        }
    }
    if(!queue.size()) send_next_time = 0;
    else send_next_time = time(0) + batch_timeout;

    //DBG("worker \'%s\' set next batch time: %lu", name.c_str(), send_next_time);
}

void PoolWorker::runTransaction(Transaction* trans, const string& sender_id, const std::string& token)
{
    string sender = sender_id;
    if(batch_size > 1 && !sender.empty()) {
        WARN("batch size of worker \'%s\' is not null, sender_id \'%s\' is not null, will ignore sender_id and erase it", name.c_str(), sender.c_str());
        sender.clear();
    }
    if(max_queue_length && queue_size.get() >= max_queue_length) {
        if(!sender.empty())
            AmSessionContainer::instance()->postEvent(
                sender, new PGResponseError("queue is full", token));
        dropped.inc((long long)trans->get_size());
        delete trans;
        return;
    }
    queue.emplace_back(trans, (ConnectionPool*)0, sender, token);
    queue_size.inc((long long)trans->get_size());
    if(!send_next_time) {
        send_next_time = time(0) + batch_timeout;
        //DBG("worker \'%s\' set next batch time: %lu", name.c_str(), send_next_time);
    }
    setWorkTimer(queue.size() >= batch_size);
}

void PoolWorker::runPrepared(const PGPrepareData& prepared)
{
    prepareds.emplace(prepared.stmt, prepared);

    std::unique_ptr<PreparedTransaction> trans;
    if(prepared.sql_types.empty()) {
        trans.reset(new PreparedTransaction(prepared.stmt, prepared.query, prepared.oids, this));
    } else {
        vector<unsigned int> oids;
        for(const auto &sql_type: prepared.sql_types) {
            auto oid = pg_typname2oid(sql_type);
            if(oid == INVALIDOID) {
                ERROR("unsupported typname '%s' for prepared statement: %s. skip",
                    sql_type.data(), prepared.stmt.data());
                return;
            }
            oids.emplace_back(oid);
        }
        trans.reset(new PreparedTransaction(prepared.stmt, prepared.query, oids, this));
    }

    if(master)
        master->runTransactionForPool(trans.get());
    if(slave)
        slave->runTransactionForPool(trans.get());
}

void PoolWorker::runInitial(IQuery *query)
{
    init_queries.emplace_back(query->clone());

    NonTransaction tr(this);
    tr.exec(query);

    if(master)
        master->runTransactionForPool(&tr);
    if(slave)
        slave->runTransactionForPool(&tr);
}

void PoolWorker::setSearchPath(const vector<string>& search_path)
{
    search_pathes = search_path;
    if(search_pathes.empty()) return;
    string query("SET search_path TO ");
    for(auto& path : search_pathes) {
        query += path + ",";
    }
    query.pop_back();

    Transaction* tr = new NonTransaction(this);
    tr->exec(new QueryParams(query, false, false));
    if(master)
        master->runTransactionForPool(tr);
    if(slave)
        slave->runTransactionForPool(tr);
    delete tr;
}

void PoolWorker::setReconnectErrors(const vector<std::string>& errors)
{
    reconnect_errors = errors;
}

void PoolWorker::configure(const PGWorkerConfig& e)
{
    prepareds.clear();
    search_pathes.clear();
    init_queries.clear();
    reconnect_errors.clear();

    failover_to_slave = e.failover_to_slave;
    retransmit_enable = e.retransmit_enable;
    use_pipeline = e.use_pipeline;
    trans_wait_time = e.trans_wait_time;
    retransmit_interval = e.retransmit_interval;
    reconnect_interval = e.reconnect_interval;
    batch_size = e.batch_size;
    batch_timeout = e.batch_timeout;
    max_queue_length = e.max_queue_length;
    conn_lifetime = e.connection_lifetime;

    setSearchPath(e.search_pathes);
    setReconnectErrors(e.reconnect_errors);
    for(auto& prepared : e.prepeared)
        runPrepared(prepared);

    if(master) master->usePipeline(use_pipeline);
    if(slave) slave->usePipeline(use_pipeline);

    reset_next_time = 0;
    resetConnections.clear();
    retransmit_next_time = 0;
    wait_next_time = 0;

    setWorkTimer(conn_lifetime);
}

void PoolWorker::resetPools(PGWorkerPoolCreate::PoolType type)
{
    if(master && type == PGWorkerPoolCreate::Master) master->resetConnections();
    if(slave && type == PGWorkerPoolCreate::Slave) slave->resetConnections();
}

void PoolWorker::resetConnection(int fd)
{
    Connection* conn = 0;
    if(master) conn = master->getConnection(fd);
    if(!conn && slave) conn = slave->getConnection(fd);
    if(conn) conn->reset();
}

void PoolWorker::resetPools()
{
    if(master) master->resetConnections();
    if(slave) slave->resetConnections();
}

void PoolWorker::onFireTransaction(const TransContainer& trans)
{
    ERROR("pg connection %s/%s:%p/%s active transaction timeout. transaction size:%d, query:%s",
          name.c_str(),
          trans.currentPool == master ? pool_type_master.data() : pool_type_slave.data(),
          trans.trans->get_conn(), trans.trans->get_conn()->getConnInfo().c_str(),
          trans.trans->get_size(),
          trans.trans->get_query()->get_query().data());

    if(!retransmit_enable &&
       (!failover_to_slave || trans.currentPool == slave) &&
       !trans.sender_id.empty())
    {
        AmSessionContainer::instance()->postEvent(
            trans.sender_id, new PGTimeout(trans.token));
    }
    trans.trans->cancel();
    canceled.inc((long long)trans.trans->get_size());
}

void PoolWorker::onErrorTransaction(const TransContainer& trans, const string& error)
{
    ERROR("pg connection %s/%s:%p/%s transaction error: '%s', transaction size:%d, query:%s",
          name.c_str(),
          trans.currentPool == master ? pool_type_master.data() : pool_type_slave.data(),
          trans.trans->get_conn(), trans.trans->get_conn()->getConnInfo().c_str(),
          error.data(),
          trans.trans->get_size(),
          trans.trans->get_query()->get_query().data());

    if(!retransmit_enable &&
       (!failover_to_slave || trans.currentPool == slave) &&
       !trans.sender_id.empty())
    {
        AmSessionContainer::instance()->postEvent(
            trans.sender_id, new PGResponseError(error, trans.token));
    } else {
        Transaction* trans_ = 0;
        if(trans.trans->get_type() == TR_NON && !use_pipeline) {
            trans_ = new NonTransaction(this);
            trans_->exec(trans.trans->get_query(false)->clone());
            retransmit_q.emplace_back(trans_, trans.currentPool, trans.sender_id, trans.token);
            ret_size.inc((long long)trans_->get_size());
        } else if(trans.trans->get_type() == TR_POLICY ||
                (trans.trans->get_type() == TR_NON && use_pipeline)){
            IQuery* query = trans.trans->get_query(true);
            int qsize = trans.trans->get_size();
            IQuery* q_ret = 0;
            if(qsize > 1) {
                q_ret = trans.trans->get_query(false);
                QueryChain* chain = dynamic_cast<QueryChain*>(query);
                assert(chain);
                chain->removeQuery(q_ret);
            }
            trans_ = trans.trans->clone();
            retransmit_q.emplace_back(trans_, trans.currentPool, trans.sender_id, trans.token);
            ret_size.inc((long long)trans.trans->get_size());
            if(qsize > 1) {
                if(trans.trans->get_type() == TR_POLICY)
                    trans_ = createDbTransaction(this, trans.trans->get_policy().il, trans.trans->get_policy().wp);
                else
                    trans_ = new NonTransaction(this);
                trans_->exec(q_ret);
                retransmit_q.emplace_back(trans_, trans.currentPool, trans.sender_id, trans.token);
                ret_size.inc((long long)trans_->get_size());
            }
        } else {
            trans_ = trans.trans->clone();
            retransmit_q.emplace_back(trans_, trans.currentPool, trans.sender_id, trans.token);
            ret_size.inc((long long)trans.trans->get_size());
        }
    }
    failed.inc((long long)trans.trans->get_size());
}

void PoolWorker::applyTimer()
{
    //DBG("applyTimer() %d, %d", minimal_timer_time, timer_is_set);
    if(minimal_timer_time && !timer_is_set) {
        workTimer.set(minimal_timer_time, false);
        timer_is_set = true;
    }
}

void PoolWorker::onTimer()
{
    minimal_timer_time = 0;
    timer_is_set = false;
    time_t now = time(0);

    for(auto& tr : erased) delete tr;
    erased.clear();

    for(auto trans_it = transactions.begin();
        trans_wait_time && trans_it != transactions.end();) {
        if(now - trans_it->createdTime > trans_wait_time &&
           trans_it->trans->get_status() == Transaction::ACTIVE)
        {
            onFireTransaction(*trans_it);
            trans_it++;
        } else if(now - trans_it->createdTime > trans_wait_time*2 &&
                  trans_it->trans->get_status() == Transaction::CANCELING)
        {
            resetConnections.insert(trans_it->trans->get_conn());
            tr_size.dec((long long)trans_it->trans->get_size());
            onErrorTransaction(*trans_it, "transaction cancel timeout");
            trans_it = transactions.erase(trans_it);
        } else {
            wait_next_time = trans_it->createdTime + trans_wait_time;
            //DBG("worker \'%s\' set next wait time %lu", name.c_str(), wait_next_time);
            trans_it++;
        }
    }

#ifdef TRANS_LOG_ENABLE
    for(auto trans_it = transactions.begin();
        PostgreSQL::instance()->getLogTime() && trans_it != transactions.end(); trans_it++) {
        if(now - trans_it->createdTime > PostgreSQL::instance()->getLogTime() &&
           trans_it->trans->get_status() == Transaction::ACTIVE) {
            trans_it->trans->saveLog();
        }
    }
#endif


    resetConnectionsContainer conns;
    conns.swap(resetConnections);
    resetConnections.clear();
    reset_next_time = 0;
    for(auto conn_it = conns.begin();
        conn_it != conns.end();)
    {
        if(now > (*conn_it)->getPendingResetTime()) {
            (*conn_it)->reset();
            conn_it = conns.erase(conn_it);
            continue;
        }
        break;
    }
    resetConnections.merge(conns);
    if(!resetConnections.empty())
        reset_next_time = resetConnections.getNearestResetTime();

    if(conn_lifetime && reconn_next_time <= now) {
        reconn_next_time = 0;
        time_t nextTime = 0;
        if(master) {
            auto conns = master->getLifetimeOverConnections(nextTime);
            for(auto& conn : conns) {
                conn->reset();
            }
        }
        if(slave) {
            auto conns = slave->getLifetimeOverConnections(nextTime);
            for(auto& conn : conns) {
                conn->reset();
            }
        }
        if(nextTime) reconn_next_time = nextTime + conn_lifetime;
    }

    checkQueue();
    setWorkTimer(false);
}

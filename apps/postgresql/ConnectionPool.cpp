#include "ConnectionPool.h"
#include "PostgreSQL.h"
#include <stdio.h>
#include <AmEventDispatcher.h>
#include <AmStatistics.h>

#define ERROR_CALLBACK \
[query, token, sender_id](const string& error) {\
    if(!sender_id.empty())\
        AmEventDispatcher::instance()->post(sender_id, new PGResponseError(query, error, token));\
}

Worker::Worker(const std::string& name, int epollfd)
: name(name), epoll_fd(epollfd)
, failover_to_slave(false)
, retransmit_enable(false)
, trans_wait_time(DEFAULT_WAIT_TIME)
, retransmit_interval(DEFAULT_RET_INTERVAL)
, reconnect_interval(DEFAULT_REC_INTERVAL)
, batch_size(DEFAULT_BATCH_SIZE)
, batch_interval(DEFAULT_BATCH_INTERVAL)
, max_queue_length(DEFAULT_MAX_Q_LEN)
, retransmit_next_time(0), wait_next_time(0)
, reset_next_time(0), send_next_time(0)
, master(0), slave(0)
, queue_size(stat_group(Gauge, MOD_NAME, "queue").addAtomicCounter().addLabel("worker", name))
, dropped(stat_group(Counter, MOD_NAME, "dropped").addAtomicCounter().addLabel("worker", name))
, ret_size(stat_group(Gauge, MOD_NAME, "retransmit").addAtomicCounter().addLabel("worker", name))
, tr_size(stat_group(Gauge, MOD_NAME, "active").addAtomicCounter().addLabel("worker", name))
, finished(stat_group(Counter, MOD_NAME, "finished").addAtomicCounter().addLabel("worker", name)) {
    workTimer.link(epoll_fd, true);
}

Worker::~Worker()
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
    if(master) delete master;
    if(slave) delete slave;
}

void Worker::getStats(AmArg& stats)
{
    stats["max_queue_length"] = max_queue_length;
    stats["batch_size"] = batch_size;
    stats["batch_interval"] = batch_interval;
    stats["trans_wait_time"] = trans_wait_time;
    stats["reconnect_interval"] = reconnect_interval;
    stats["retransmit_interval"] = retransmit_interval;
    stats["retransmit_enable"] = retransmit_enable;
    stats["failover_to_slave"] = failover_to_slave;
    stats["queue"] = (long long)queue_size.get();
    stats["retransmit"] = (long long)ret_size.get();
    stats["dropped"] = (long long)dropped.get();
    stats["active"] = (long long)tr_size.get();
    stats["finished"] = (long long)finished.get();
    if(master)
        master->getStats(stats["master"]);
    if(slave)
        slave->getStats(stats["slave"]);
}

void Worker::onConnect(IPGConnection* conn) {
    DBG("connection %s:%p/\'%s\' success", name.c_str(), conn, conn->getConnInfo().c_str());
    if(!prepareds.empty() || !search_pathes.empty()) {
        IPGTransaction* trans = new ConfigTransaction(prepareds, search_pathes, this);
        if(!conn->runTransaction(trans)) {
            ERROR("connection %p/%s of worker \'%s\' already exist transaction", conn, conn->getConnInfo().c_str(), name.c_str());
            delete trans;
        }
    }
    else
        setWorkTimer(true);
}
void Worker::onReset(IPGConnection* conn) {
    DBG("pg connection %s:%p/\'%s\' reset", name.c_str(), conn, conn->getConnInfo().c_str());
}
void Worker::onPQError(IPGConnection* conn, const std::string& error) {
    ERROR("pg connection %s:%p/\'%s\' error: %s", name.c_str(), conn, conn->getConnInfo().c_str(), error.c_str());
}

void Worker::onStopTransaction(IPGTransaction* trans)
{
    ERROR("pg connection %s:%p/\'%s\' stopped transaction %s",
          name.c_str(), trans->get_conn(), trans->get_conn()->getConnInfo().c_str(), trans->get_query()->get_query().c_str());
    for(auto tr_it = transactions.begin();
        tr_it != transactions.end(); tr_it++) {
        if(trans == tr_it->trans) {
            retransmit_q.emplace_back(tr_it->trans, (ConnectionPool*)0, tr_it->sender_id, tr_it->token);
            tr_size.dec((long long)tr_it->trans->get_size());
            ret_size.inc((long long)tr_it->trans->get_size());
            transactions.erase(tr_it);
            return;
        }
    }
}

void Worker::onConnectionFailed(IPGConnection* conn, const std::string& error) {
    DBG("pg connection %s:%p/\'%s\' failed: %s", name.c_str(), conn, conn->getConnInfo().c_str(), error.c_str());
    resetConnections.push_back(conn);
    reset_next_time = resetConnections[0]->getDisconnectedTime() + reconnect_interval;
    DBG("worker \'%s\' set next reset time: %lu", name.c_str(), reset_next_time);
    setWorkTimer(false);
}
void Worker::onDisconnect(IPGConnection* conn) {
    DBG("pg connection %s:%p/\'%s\' disconnect", name.c_str(), conn, conn->getConnInfo().c_str());
    resetConnections.push_back(conn);
    reset_next_time = resetConnections[0]->getDisconnectedTime();
    DBG("worker \'%s\' set next reset time: %lu", name.c_str(), reset_next_time);
    setWorkTimer(false);
}

void Worker::onSock(IPGConnection* conn, IConnectionHandler::EventType type)
{
    if(type == PG_SOCK_NEW) {
        epoll_event event;
        event.events = EPOLLIN | EPOLLERR | EPOLLET;
        event.data.ptr = conn;

        // add the socket to the epoll file descriptors
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn->getSocket(), &event);
    } else if(type == PG_SOCK_DEL) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->getSocket(), nullptr);
    } else {
        epoll_event event;
        event.events = EPOLLERR;
        event.data.ptr = conn;
        if(type == PG_SOCK_WRITE) event.events |= EPOLLOUT;
        if(type == PG_SOCK_READ) event.events |= EPOLLIN;

        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->getSocket(), &event);
    }
}

void Worker::onError(IPGTransaction* trans, const string& error) {
    ERROR("Error of transaction \'%s\' : %s", trans->get_query()->get_query().c_str(), error.c_str());
    for(auto tr_it = transactions.begin();
        tr_it != transactions.end(); tr_it++) {
        if(trans == tr_it->trans) {
            onErrorTransaction(*tr_it, error);
            tr_size.dec((long long)tr_it->trans->get_size());
            transactions.erase(tr_it);
            return;
        }
    }
}

void Worker::onTuple(IPGTransaction* trans, const AmArg& result) {
}

void Worker::onFinish(IPGTransaction* trans, const AmArg& result) {
    setWorkTimer(true);
    erased.push_back(trans);
    DBG("transaction query \'%s\' finished", trans->get_query()->get_query().c_str());
    for(auto tr_it = transactions.begin();
        tr_it != transactions.end(); tr_it++){
        if(trans == tr_it->trans) {
            DBG("return result \'%s\'", AmArg::print(result).c_str());
            if(!tr_it->sender_id.empty())
                AmEventDispatcher::instance()->post(tr_it->sender_id, new PGResponse(trans->get_query()->get_query(), result, tr_it->token));
            finished.inc((long long)tr_it->trans->get_size());
            tr_size.dec((long long)tr_it->trans->get_size());
            transactions.erase(tr_it);
            return;
        }
    }
}

void Worker::onPQError(IPGTransaction* trans, const std::string& error) {
    DBG("Error of transaction \'%s\' : %s", trans->get_query()->get_query().c_str(), error.c_str());
    for(auto tr_it = transactions.begin();
        tr_it != transactions.end(); tr_it++) {
        if(trans == tr_it->trans) {
            onErrorTransaction(*tr_it, error);
            tr_size.dec((long long)tr_it->trans->get_size());
            transactions.erase(tr_it);
            return;
        }
    }
}

void Worker::onCancel(IPGTransaction* conn) {
    DBG("transaction with query %s canceling", conn->get_query()->get_query().c_str());
}

bool Worker::processEvent(void* p)
{
    if(p == &workTimer) {
        onTimer();
        workTimer.read();
        return true;
    }
    return false;
}

void Worker::createPool(PGWorkerPoolCreate::PoolType type, const PGPool& pool)
{
    if(type == PGWorkerPoolCreate::Master) {
        if(!master) master = new ConnectionPool(pool, this);
        else ERROR("master connection pool of worker %s already created", name.c_str());
    }
    if(type == PGWorkerPoolCreate::Slave) {
        if(!slave) slave = new ConnectionPool(pool, this);
        else ERROR("slave connection pool of worker %s already created", name.c_str());
    }
}

void Worker::getFreeConnection(IPGConnection **conn, ConnectionPool **pool, std::function<void(const string&)> func)
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
int Worker::retransmitTransaction(TransContainer& trans)
{
    retransmit_next_time = 0;
    bool is_ret_timer_set = false;
    time_t current_time = time(0);
    if(!trans.currentPool) {
        IPGConnection* conn = 0;
        ConnectionPool* pool = 0;
        string query = trans.trans->get_query()->get_query();
        string sender_id = trans.sender_id;
        string token = trans.token;
        getFreeConnection(&conn, &pool, ERROR_CALLBACK);
        if(!conn) return -1;
        transactions.emplace_back(trans.trans, pool, sender_id, token);
        tr_size.inc((long long)trans.trans->get_size());
        wait_next_time = transactions.front().createdTime + trans_wait_time;
        DBG("worker \'%s\' set next wait time %lu", name.c_str(), wait_next_time);
        conn->runTransaction(trans.trans);
        setWorkTimer(false);
        return 0;
    } else if(trans.currentPool == master){
        if(!failover_to_slave && !retransmit_enable) {
            delete trans.trans;
            return 0;
        } else if(current_time - trans.createdTime < retransmit_interval) {
            if(!is_ret_timer_set) {
                retransmit_next_time = trans.createdTime + retransmit_interval;
                is_ret_timer_set = true;
                DBG("worker \'%s\' set next retransmit time: %lu", name.c_str(), retransmit_next_time);
            }
            return 1;
        }
        IPGConnection* conn = 0;
        ConnectionPool* pool = master;
        string query = trans.trans->get_query()->get_query();
        string sender_id = "";
        string token = trans.token;
        getFreeConnection(&conn, &pool, ERROR_CALLBACK);
        if(failover_to_slave && slave && !conn)
            return 1;
        else if(failover_to_slave && conn) {
            transactions.emplace_back(trans.trans, pool, trans.sender_id, token);
            tr_size.inc((long long)trans.trans->get_size());
            wait_next_time = transactions.front().createdTime + trans_wait_time;
            DBG("worker \'%s\' set next wait time %lu", name.c_str(), wait_next_time);
            setWorkTimer(false);
            conn->runTransaction(trans.trans);
            return 0;
        } else if((failover_to_slave && !slave) ||
                  !failover_to_slave) {
            if(!retransmit_enable) {
                delete trans.trans;
                return 0;
            } else {
                trans.currentPool = 0;
                return retransmitTransaction(trans);
            }
        }
    } if(!retransmit_enable) {
        delete trans.trans;
        return 0;
    } else if(current_time - trans.createdTime < retransmit_interval) {
        if(!is_ret_timer_set) {
            retransmit_next_time = trans.createdTime + retransmit_interval;
            is_ret_timer_set = true;
            DBG("worker \'%s\' set next retransmit time: %lu", name.c_str(), retransmit_next_time);
        }
        return 1;
    }

    trans.currentPool = 0;
    return retransmitTransaction(trans);
}

void Worker::setWorkTimer(bool immediately)
{
    time_t current = time(0);
    if(immediately) {
        workTimer.set(1, false);
        //DBG("set timer immediately");
    } else {
        time_t interval = 0;
        if(reset_next_time && 
          (!interval || reset_next_time < current || reset_next_time - current < interval)) {
            interval = reset_next_time - current > 0 ? reset_next_time - current : 1;
        }
        if(retransmit_next_time &&
          (!interval || retransmit_next_time < current || retransmit_next_time - current < interval)) {
            interval = retransmit_next_time - current > 0 ? retransmit_next_time - current : 1;
        }
        if(wait_next_time &&
          (!interval || wait_next_time < current || wait_next_time - current < interval)) {
            interval = wait_next_time - current > 0 ? wait_next_time - current : 1;
        }
        if(send_next_time &&
          (!interval || send_next_time < current || send_next_time - current < interval)) {
            interval = send_next_time - current > 0 ? send_next_time - current : 1;
        }
        workTimer.set(interval*1000000, false);
        //DBG("set timer %lu", interval);
    }
    //DBG("current_time - %lu, reset_next_time - %lu, retransmit_next_time - %lu, wait_next_time - %lu, send_next_time - %lu",
    //    current, reset_next_time, retransmit_next_time, wait_next_time, send_next_time);
}

void Worker::checkQueue()
{
    for(auto trans_it = retransmit_q.begin();
        trans_it != retransmit_q.end();) {
        int ret = retransmitTransaction(*trans_it);
        if(ret < 0) break;
        else if(ret > 0) trans_it++;
        else {
            ret_size.dec((long long)trans_it->trans->get_size());
            trans_it = retransmit_q.erase(trans_it);
        }
    }

    if(send_next_time > time(0) && queue.size() < batch_size) return;

    IPGTransaction* trans = 0;
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
                break;
            } else {
                for(auto it = queue.begin(); it != next_it; it++)
                    delete it->trans;
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
    else send_next_time = time(0) + batch_interval;
    DBG("worker \'%s\' set next batch time: %lu", name.c_str(), send_next_time);
}

void Worker::runTransaction(IPGTransaction* trans, const string& sender_id, const std::string& token)
{
    string sender = sender_id;
    if(batch_size > 1 && !sender.empty()) {
        WARN("batch size of worker \'%s\' is not null, sender_id \'%s\' is not null, will ignore sender_id and erase it", name.c_str(), sender.c_str());
        sender.clear();
    }
    if(max_queue_length && queue_size.get() >= max_queue_length) {
        if(!sender.empty())
            AmEventDispatcher::instance()->post(sender, new PGResponseError(trans->get_query()->get_query(), "queue is full", token));
        dropped.inc((long long)trans->get_size());
        delete trans;
        return;
    }
    queue.emplace_back(trans, (ConnectionPool*)0, sender, token);
    queue_size.inc((long long)trans->get_size());
    if(!send_next_time) {
        send_next_time = time(0) + batch_interval;
        DBG("worker \'%s\' set next batch time: %lu", name.c_str(), send_next_time);
    }
    setWorkTimer(false);
}

void Worker::runPrepared(const PGPrepareData& prepared)
{
    prepareds.emplace(prepared.stmt, prepared);
    PreparedTransaction trans(prepared.stmt, prepared.query, prepared.oids, this);
    if(master)
        master->runTransaction(&trans);
    if(slave)
        slave->runTransaction(&trans);
}

void Worker::setSearchPath(const vector<string>& search_path)
{
    search_pathes = search_path;
    if(search_pathes.empty()) return;
    string query("SET search_path TO ");
    for(auto& path : search_pathes) {
        query += path + ",";
    }
    query.pop_back();

    IPGTransaction* tr = new NonTransaction(this);
    tr->exec(new Query(query, false));
    if(master)
        master->runTransaction(tr);
    if(slave)
        slave->runTransaction(tr);
}

void Worker::configure(const PGWorkerConfig& e)
{
    prepareds.clear();
    failover_to_slave = e.failover_to_slave;
    retransmit_enable = e.retransmit_enable;
    trans_wait_time = e.trans_wait_time;
    retransmit_interval = e.retransmit_interval;
    reconnect_interval = e.reconnect_interval;
    batch_size = e.batch_size;
    batch_interval = e.batch_interval;
    max_queue_length = e.max_queue_length;
    setSearchPath(search_pathes);
    for(auto& prepared : e.prepeared)
        runPrepared(prepared);

    reset_next_time = 0;
    resetConnections.clear();
    retransmit_next_time = 0;
    wait_next_time = 0;
    setWorkTimer(false);
}

void Worker::resetPools()
{
    if(master) master->resetConnections();
    if(slave) slave->resetConnections();
}

void Worker::onFireTransaction(const TransContainer& trans)
{
    if(!retransmit_enable && !failover_to_slave && !trans.sender_id.empty())
        AmEventDispatcher::instance()->post(trans.sender_id, new PGTimeout(trans.trans->get_query()->get_query(), trans.token));
    trans.trans->cancel();
}

void Worker::onErrorTransaction(const Worker::TransContainer& trans, const string& error)
{
    if(!retransmit_enable && !failover_to_slave && !trans.sender_id.empty())
        AmEventDispatcher::instance()->post(trans.sender_id, new PGResponseError(trans.trans->get_query()->get_query(), error, trans.token));
    else {
        IPGTransaction* trans_ = 0;
        if(trans.trans->get_type() == TR_NON) {
            trans_ = new NonTransaction(this);
            trans_->exec(trans.trans->get_query()->get_current_query()->clone());
            retransmit_q.emplace_back(trans_, trans.currentPool, trans.sender_id, trans.token);
            ret_size.inc((long long)trans_->get_size());
        } else if(trans.trans->get_type() == TR_POLICY){
            IPGQuery* query = trans.trans->get_query();
            int qsize = query->get_size();
            IPGQuery* q_ret = 0;
            if(qsize > 1) {
                q_ret = query->get_current_query();
                QueryChain* chain = dynamic_cast<QueryChain*>(query);
                assert(chain);
                chain->removeQuery(q_ret);
            }
            trans_ = trans.trans->clone();
            retransmit_q.emplace_back(trans_, trans.currentPool, trans.sender_id, trans.token);
            ret_size.inc((long long)trans.trans->get_size());
            if(qsize > 1) {
                trans_ = createDbTransaction(this, trans.trans->get_policy().il, trans.trans->get_policy().wp);
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
}

void Worker::onTimer()
{
    time_t current = time(0);

    for(auto& tr : erased) delete tr;
    erased.clear();

    auto conns = resetConnections;
    resetConnections.clear();
    reset_next_time = 0;
    for(auto conn_it = conns.begin();
        conn_it != conns.end();) {
        if((*conn_it)->getDisconnectedTime() + reconnect_interval < current) {
            (*conn_it)->reset();
            conn_it = conns.erase(conn_it);
            continue;
        }
        reset_next_time = current - (*conn_it)->getDisconnectedTime() + reconnect_interval;
        DBG("worker \'%s\' set next reset time: %lu", name.c_str(), reset_next_time);
        break;
    }
    resetConnections.insert(resetConnections.begin(), conns.begin(), conns.end());

    for(auto trans_it = transactions.begin();
        trans_it != transactions.end();) {
        if(current - trans_it->createdTime > trans_wait_time &&
            trans_it->trans->get_status() != IPGTransaction::CANCELING) {
            onFireTransaction(*trans_it);
        } else if(current - trans_it->createdTime > trans_wait_time*2 &&
                trans_it->trans->get_status() == IPGTransaction::CANCELING) {
            resetConnections.emplace_back(trans_it->trans->get_conn());
        } else {
            wait_next_time = trans_it->createdTime + trans_wait_time;
            DBG("worker \'%s\' set next wait time %lu", name.c_str(), wait_next_time);
            trans_it++;
        }
    }
    checkQueue();
    setWorkTimer(false);
}

ConnectionPool::ConnectionPool(const PGPool& pool, Worker* worker)
: pool(pool), worker(worker) {
    string conn_info;
    int size = snprintf((char*)conn_info.c_str(), 0, "host=%s port=%d user=%s dbname=%s password=%s",
             pool.host.c_str(), pool.port, pool.user.c_str(), pool.name.c_str(), pool.pass.c_str());
    conn_info.resize(size + 1);
    snprintf((char*)conn_info.c_str(), conn_info.size(), "host=%s port=%d user=%s dbname=%s password=%s",
             pool.host.c_str(), pool.port, pool.user.c_str(), pool.name.c_str(), pool.pass.c_str());
    for(int i = 0; i < pool.pool_size; i++) {
        connections.push_back(PolicyFactory::instance()->createConnection(conn_info, worker));
        connections.back()->reset();
    }
}

ConnectionPool::~ConnectionPool()
{
    for(auto& conn : connections) delete conn;
}

IPGConnection * ConnectionPool::getFreeConnection()
{
    for(auto& conn : connections) {
        if(!conn->isBusy() && conn->getStatus() == CONNECTION_OK) return conn;
    }
    return 0;
}

void ConnectionPool::runTransaction(IPGTransaction* trans)
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

void ConnectionPool::getStats(AmArg& stats)
{
    for(auto& conn : connections) {
        AmArg conn_info;
        conn_info["status"] = conn->getStatus();
        conn_info["socket"] = conn->getSocket();
        conn_info["busy"] = conn->isBusy();
        stats.push(conn_info);
    }
}

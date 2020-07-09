#include "AmStunProcessor.h"
#include "AmStunConnection.h"
#include "AmUtils.h"
#include "sip/ip_util.h"

#define STUN_TIMER_INTERVAL_MICROSECONDS 125000

AmStunProcessor::AmStunProcessor()
  : epoll_fd(-1),
    stopped(false)
{
    if((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create failed");
        return;
    }

    timer.set(STUN_TIMER_INTERVAL_MICROSECONDS);
    timer.link(epoll_fd);
}

AmStunProcessor::~AmStunProcessor()
{
    if(-1!=epoll_fd)
        close(epoll_fd);
}

void AmStunProcessor::run()
{
    int ret;
    struct epoll_event events[1];

    setThreadName("stun-timer");

    stopped = false;
    do {
       ret = epoll_wait(epoll_fd, events, 1, -1);

       if(ret < 1) {
           if(errno != EINTR){
               ERROR("epoll_wait: %m");
               break;
           }
           continue;
       }

       if(ret > 0) {
           timer.read();
           on_timer();
       }
    } while(!stopped);

    DBG("stun processor stopped");
}

void AmStunProcessor::on_stop()
{
    stopped = true;
}

void AmStunProcessor::dispose()
{
    stop(true);
}

void AmStunProcessor::set_timer(AmStunConnection *connection, unsigned long long timeout)
{
    DBG("AmStunProcessor::set_timer connection: %p, timeout: %llu",
        connection, timeout);
    AmLock l(set_timer_events_mutex);
    set_timer_events.emplace_back(connection, timeout);
}

void AmStunProcessor::remove_timer(AmStunConnection *connection)
{
    DBG("AmStunProcessor::remove_timer for %p", connection);

    connections_mutex.lock();
    set_timer_events_mutex.lock();

    connections.erase(connection);

    auto i = set_timer_events.begin();
    while(i != set_timer_events.end()) {
        if(i->connection == connection) i = set_timer_events.erase(i);
        else ++i;
    }

    set_timer_events_mutex.unlock();
    connections_mutex.unlock();
}

void AmStunProcessor::on_timer()
{
    auto now = wheeltimer::instance()->unix_ms_clock.get();

    //DBG("AmStunProcessor::on_timer %llu", now);

    //process connections
    connections_mutex.lock();
    auto i = connections.begin();
    while(i != connections.end()) {
        /*DBG("AmStunProcessor::on_timer process connection: %p, now: %llu, timeout: %llu",
            i->first, now, i->second);*/
        if(now > i->second) {
            //DBG("send_request for connection %p", i->first);
            i->first->send_request();
            i = connections.erase(i);
            continue;
        }
        ++i;
    }
    connections_mutex.unlock();

    //process add_timer_events
    AmLock timer_events_lock(set_timer_events_mutex);

    while(!set_timer_events.empty()) {
        auto &e = set_timer_events.front();
        /*DBG("AmStunProcessor::process set timer event: %p, %llu",
            e.connection, e.timeout);*/
        connections[e.connection] = now + e.timeout;
        set_timer_events.pop_front();
    }
}

#if 0
bool AmStunProcessor::exist(const sockaddr_storage* addr)
{
    bool res;

    sp_bucket_base* bucket = get_bucket(hashlittle(addr, SA_len(addr), 0) & STUN_PEER_HT_MASK);

    bucket->lock();
    res = bucket->exist(*(const sp_addr*)addr);
    bucket->unlock();

    return res;
}

void AmStunProcessor::insert(const sockaddr_storage* addr, AmStunConnection* conn)
{
    DBG("AmStunProcessor::insert(%s:%hu/%hhu,%p)",
        get_addr_str(addr).data(),
        am_get_port(addr),
        SA_transport(const_cast<sockaddr_storage * >(addr)),
        conn);

    sp_bucket_base* bucket = get_bucket(hashlittle(addr, SA_len(addr), 0) & STUN_PEER_HT_MASK);

    bucket->lock();
    if(!bucket->exist(*(const sp_addr*)addr)) {
        bucket->insert(*(const sp_addr*)addr,conn);
    } else {
        DBG("AmStunProcessor::insert() entry exists. insert skipped");
    }
    bucket->unlock();
}

void AmStunProcessor::remove(const sockaddr_storage* addr)
{
    DBG("AmStunProcessor::remove(%s:%hu/%hhu)",
        get_addr_str(addr).data(),
        am_get_port(addr),
        SA_transport(const_cast<sockaddr_storage * >(addr)));

    sp_bucket_base* bucket = get_bucket(hashlittle(addr, SA_len(addr), 0) & STUN_PEER_HT_MASK);

    bucket->lock();
    bucket->remove(*(const sp_addr*)addr);
    bucket->unlock();
}

void AmStunProcessor::fire(const sockaddr_storage* addr)
{
    //DBG("AmStunProcessor::fire(%s)", get_addr_str(addr).data());
    sp_bucket_base* bucket = get_bucket(hashlittle(addr, SA_len(addr), 0) & STUN_PEER_HT_MASK);

    bucket->lock();
    auto c = bucket->get(addr);
    if(c) {
        c->send_request();
    }
    bucket->unlock();
}
#endif

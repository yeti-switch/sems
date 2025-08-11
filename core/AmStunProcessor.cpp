#include "AmStunProcessor.h"
#include "media/AmStunConnection.h"
#include "AmUtils.h"
#include "sip/ip_util.h"

#define STUN_TIMER_INTERVAL_MICROSECONDS STUN_TA_TIMEOUT * 1000

AmStunProcessor::AmStunProcessor()
    : epoll_fd(-1)
    , stopped(false)
{
    if ((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create failed");
        return;
    }

    timer.set(STUN_TIMER_INTERVAL_MICROSECONDS);
    timer.link(epoll_fd);
}

AmStunProcessor::~AmStunProcessor()
{
    if (-1 != epoll_fd)
        close(epoll_fd);
}

void AmStunProcessor::run()
{
    int                ret;
    struct epoll_event events[1];

    setThreadName("stun-timer");

    stopped = false;
    do {
        ret = epoll_wait(epoll_fd, events, 1, -1);

        if (ret < 1) {
            if (errno != EINTR) {
                ERROR("epoll_wait: %m");
                break;
            }
            continue;
        }

        if (ret > 0) {
            timer.read();
            on_timer();
        }
    } while (!stopped);

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

void AmStunProcessor::add_ice_context(IceContext *context)
{
    AmLock l(connections_mutex);
    for (auto ctx : contexts) {
        if (context == ctx)
            return;
    }

    DBG("AmStunProcessor::add ice context type: %d, stream %p", context->getType(), context->getStream());
    contexts.push_back(context);
}

void AmStunProcessor::remove_ice_context(IceContext *context)
{
    DBG("AmStunProcessor::remove ice context type: %d, stream %p", context->getType(), context->getStream());
    AmLock l(connections_mutex);
    auto   ctx = contexts.begin();
    while (ctx != contexts.end()) {
        if (context == *ctx) {
            contexts.erase(ctx);
            return;
        }
        ctx++;
    }
}

void AmStunProcessor::set_timer(AmStunConnection *connection, unsigned long long timeout)
{
    DBG("AmStunProcessor::set_timer connection: %p, timeout: %llu", connection, timeout);
    AmLock l(connections_mutex);
    inc_ref(connection);
    auto now                = wheeltimer::instance()->unix_ms_clock.get();
    connections[connection] = now + timeout;
}

void AmStunProcessor::remove_timer(AmStunConnection *connection)
{
    DBG("AmStunProcessor::remove_timer for %p", connection);
    AmLock l(connections_mutex);
    if (connections.erase(connection))
        dec_ref(connection);
}

void AmStunProcessor::on_timer()
{
    auto now = wheeltimer::instance()->unix_ms_clock.get();

    // DBG("AmStunProcessor::on_timer %llu", now);

    AmLock connections_lock(connections_mutex);
    // process connections
    auto i = connections.begin();
    while (i != connections.end()) {
        if (now > i->second) {
            i->first->checkState();
            if (auto interval = i->first->checkStunTimer(); interval.has_value()) {
                i->second = now + interval.value();
            } else {
                dec_ref(i->first);
                i = connections.erase(i);
                continue;
            }
        }
        ++i;
    }

    std::unordered_map<AmStunConnection *, unsigned long long> new_conns;
    for (auto context : contexts) {
        context->updateStunTimers(new_conns);
    }
    for (auto conn : new_conns) {
        if (connections.find(conn.first) == connections.end()) {
            inc_ref(conn.first);
            connections[conn.first] = now + conn.second;
        }
    }
}

#include "RedisConnectionPool.h"
#include "RedisConnection.h"

#include <AmEventDispatcher.h>

#define EPOLL_MAX_EVENTS 2048
#define session_container AmSessionContainer::instance()
#define event_dispatcher AmEventDispatcher::instance()

int parseReply(redisReply *reply, RedisReply::result_type &result, AmArg &data)
{
    if(!reply) {
        result = RedisReply::IOError;
        return -1;
    }

    //serialize redisReply to AmArg
    if(redis::isReplyError(reply)) {
        result = RedisReply::ErrorReply;
        //data = string("error: ") + string(reply->str,reply->len);
    } else if(redis::isReplyStatus(reply)) {
        result = RedisReply::StatusReply;
        //data = string("status: ") + string(reply->str,reply->len);
    } else {
        result = RedisReply::SuccessReply;
    }

    redisReply2Amarg(data, reply);
    return 0;
}

static void redis_request_cb_static(redisAsyncContext *, void *r, void *privdata)
{
    RedisReplyCtx *ctx = static_cast<RedisReplyCtx *>(privdata);
    redisReply* reply = static_cast<redisReply *>(r);
    DBG("got reply from redis");
    if(reply == nullptr) {
        ERROR("%s: I/O error", ctx->session_id.c_str());
    } else if(redis::isReplyError(reply)) {
        ERROR("%s: error: %s", ctx->session_id.c_str(), redis::getReplyError(reply));
    }

    RedisReply::result_type result;
    AmArg data;
    parseReply(reply, result, data);
    //DBG("reply data %s", >data.print().c_str());

    if(ctx->pool)
        ctx->pool->process_internal_reply(ctx->c, result, ctx->user_data.release(), data);
    else if(ctx->session_id.empty() == false)
        session_container->postEvent(ctx->session_id,
            new RedisReply(ctx->conn_id, result, data, ctx->user_data, ctx->user_type_id));

    if(!ctx->persistent_ctx) delete ctx;
}

RedisConnectionPool::RedisConnectionPool(const char* name, const string &queue_name)
  : AmEventFdQueue(this),
    epoll_fd(-1),
    name(name),
    queue_name(queue_name),
    stopped(false)
{
    event_dispatcher->addEventQueue(queue_name, this);
}

RedisConnectionPool::~RedisConnectionPool()
{
    CLASS_DBG("RedisConnectionPool::~RedisConnectionPool()");
    event_dispatcher->delEventQueue(queue_name);

    for(auto &ctx: persistent_reply_contexts)
        delete ctx;

    while(!connections.empty()) {
        delete connections.front();
        connections.pop_front();
    }
}

int RedisConnectionPool::init()
{
    if((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    stop_event.link(epoll_fd,true);

    reconnect_timer.link(epoll_fd,true);
    reconnect_timer.set(2e6,true);

    retry_reqs_timer.link(epoll_fd,true);
    retry_reqs_timer.set(0,false);

    epoll_link(epoll_fd,true);
    return 0;
}

void RedisConnectionPool::run()
{
    int ret;
    void *p;
    bool running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    setThreadName(name);

    DBG("start async redis '%s'", name);

    auto self_queue_ptr = dynamic_cast<AmEventFdQueue *>(this);
    running = true;
    do {
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if(ret == -1 && errno != EINTR){
            ERROR("epoll_wait: %s",strerror(errno));
        }

        if(ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            p = e.data.ptr;
            if(p==&reconnect_timer) {
                reconnect_timer.read();
                reconnect();
            } else if(p==&retry_reqs_timer) {
                retry_reqs_timer.read();
                on_retry_reqs_timer();
            } else if(p==&stop_event) {
                process_stop_event();
                stop_event.read();
                running = false;
                break;
            } else if(p==self_queue_ptr) {
                processEvents();
            } else {
                if(!p) {
                    CLASS_ERROR("got event on null async_context. ignore");
                    continue;
                }
                if(e.events & EPOLLIN) {
                    redis::redisAsyncHandleRead((redisAsyncContext*)p);
                }
                if(e.events & EPOLLOUT) {
                    redis::redisAsyncHandleWrite((redisAsyncContext*)p);
                }
            }
        }
    } while(running);

    epoll_unlink(epoll_fd);
    close(epoll_fd);

    DBG("async redis '%s' stopped", name);

    stopped.set(true);
}

void RedisConnectionPool::process(AmEvent* ev)
{
    switch(ev->event_id) {
        case E_SYSTEM: {
            AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(ev);
            if(sys_ev && sys_ev->sys_event == AmSystemEvent::ServerShutdown){
                stop_event.fire();
            }
            return;
        }
    }
}

void RedisConnectionPool::process_request_event(RedisRequest& event, RedisConnection *c)
{
    redisAsyncContext* context = c->get_async_context();
    if(c->is_connected() == false) {
        if(event.session_id.empty() == false)
            session_container->postEvent(event.session_id,
                new RedisReply(event.conn_id, RedisReply::NotConnected, AmArg(),
                    event.user_data, event.user_type_id));
        return;
    }

    // args
    vector<string> args(event.args.size());
    for(int i = 0; i < event.args.size(); i++) {
        AmArg &child = event.args[i];

        if(isArgCStr(child)) {
            args[i] = std::string(child.asCStr());
            continue;
        }

        if(isArgInt(child)) {
            std::ostringstream strs;
            strs << child.asInt();
            args[i] = strs.str();
            continue;
        }

        if(isArgLongLong(child)) {
            std::ostringstream strs;
            strs << child.asLongLong();
            args[i] = strs.str();
            continue;
        }

        if(isArgDouble(child)) {
            std::ostringstream strs;
            strs << child.asDouble();
            args[i] = strs.str();
            continue;
        }

        DBG("Unsupported arg type in pos %d", i);
        break;
    }

    vector<const char*> argv(args.size());
    vector<size_t> argvlen(args.size());
    for(int i = 0; i < args.size(); ++i) {
        argv[i] = args[i].c_str();
        argvlen[i] = args[i].length();
    }

    char *cmd = nullptr;
    int ret = redis::redisFormatCommandArgv(&cmd, args.size(), argv.data(), argvlen.data());
    //DBG("cmd %s ret %d", cmd, ret);

    if(ret <= 0)
        return;

    if(event.user_data && event.persistent_ctx) {
        ERROR("%s:%d user_data is not allowed for persistent context. clear it",
            event.session_id.data(), event.user_type_id);
        event.user_data.reset();
    }

    size_t cmd_size = static_cast<size_t>(ret);
    auto ctx = new RedisReplyCtx(c,event);
    if(REDIS_OK != redis::redisAsyncFormattedCommand(context, &redis_request_cb_static, ctx, cmd, cmd_size)) {
        if(event.session_id.empty() == false)
            session_container->postEvent(ctx->session_id,
            new RedisReply(event.conn_id, RedisReply::FailedToSend, AmArg(),
                    event.user_data, event.user_type_id));

        delete ctx; ctx = nullptr;
        delete cmd; cmd = nullptr;
        return;
    }
    //set reply ctx for persistent contexts
    if(ctx->persistent_ctx) {
        persistent_reply_contexts.push_back(ctx);
    }

    delete cmd; cmd = nullptr;
}

void RedisConnectionPool::process_internal_request(RedisConnection *c, AmObject *user_data, const char *fmt...)
{
    va_list args;
    va_start(args, fmt);
    process_internal_vrequest(c, user_data, fmt, args);
    va_end(args);
}

void RedisConnectionPool::process_internal_vrequest(RedisConnection *c, AmObject *user_data, const char *fmt, va_list args)
{
    redisAsyncContext* context = c->get_async_context();
    if(c->is_connected() == false)
        return;

    char *cmd;
    int ret = redis::redisvFormatCommand(&cmd, fmt, args);
    if(ret <= 0)
        return;

    size_t cmd_size = static_cast<size_t>(ret);
    auto ctx = new RedisReplyCtx(c, user_data, this);
    if(REDIS_OK != redis::redisAsyncFormattedCommand(context, &redis_request_cb_static, ctx, cmd, cmd_size)) {
        delete ctx; ctx = nullptr;
    }

    delete cmd; cmd = nullptr;
}

void RedisConnectionPool::process_stop_event()
{
    for(auto& connection : connections)
        if(connection->is_connected())
            redis::redisAsyncDisconnect(connection->get_async_context());
}

RedisConnection* RedisConnectionPool::addConnection(const std::string& host, int port)
{
    RedisConnection* conn = new RedisConnection(name, this);
    if(conn->init(epoll_fd, host, port) != 0) {
        delete conn;
        return 0;
    }

    connections.push_back(conn);
    return conn;
}

void RedisConnectionPool::reconnect()
{
    for(auto& connection : connections)
        connection->reconnect();
}

void RedisConnectionPool::init_retry_reqs_timer(unsigned int timeout_ms)
{
    retry_reqs_timer.set(timeout_ms * 1000, false);
}

void RedisConnectionPool::on_stop()
{
    stop_event.fire();
    stopped.wait_for();
}
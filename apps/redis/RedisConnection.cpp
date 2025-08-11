#include "RedisConnection.h"
#include "AmSessionContainer.h"

#include <fstream>
#include <string>

#define EPOLL_MAX_EVENTS 2048


RedisConnection::RedisConnection(const char *name, RedisConnectionStateListener *state_listener)
    : async_context(0)
    , connected(false)
    , master(false)
    , needAutorization(false)
    , name(name)
    , state_listener(state_listener)
{
    RedisConnection::host = "127.0.0.1";
    RedisConnection::port = 6379;
}

RedisConnection::~RedisConnection()
{
    CLASS_DBG("RedisConnection::~RedisConnection()");
}

static void connectCallback_static(const redisAsyncContext *c, int status)
{
    RedisConnection *conn = static_cast<RedisConnection *>(redis::redisAsyncGetData(c));
    conn->connectCallback(c, status);
}

void RedisConnection::connectCallback(const struct redisAsyncContext *c, int status)
{
    if (status == REDIS_OK) {
        INFO("redis %s[%p] %s:%d connected", name.c_str(), c, host.c_str(), port);
        on_connect();
    } else {
        ERROR("redis %s[%p] %s:%d: %s", name.c_str(), c, host.c_str(), port, redis::redisGetError((void *)c));
        on_disconnect();
    }
}

static void disconnectCallback_static(const redisAsyncContext *c, int status)
{
    RedisConnection *conn = static_cast<RedisConnection *>(redis::redisAsyncGetData(c));
    conn->disconnectCallback(c, status);
}
void RedisConnection::disconnectCallback(const redisAsyncContext *c, int status)
{
    if (status == REDIS_OK) {
        INFO("redis %s[%p] %s:%d disconnected", name.c_str(), c, host.c_str(), port);
    } else {
        ERROR("redis %s[%p] %s:%d: %s", name.c_str(), c, host.c_str(), port, redis::redisGetError((void *)c));
    }
    on_disconnect();
}

static int add_event_static(void *c, int flag)
{
    RedisConnection *conn = static_cast<RedisConnection *>(c);
    return conn->add_event(flag);
}

int RedisConnection::add_event(int flag)
{
    struct epoll_event ee = {};
    int                op = mask ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;

    ee.events   = static_cast<uint32_t>(mask |= flag);
    ee.data.ptr = async_context;

    return epoll_ctl(epoll_fd, op, redis::redisGetFd(async_context), &ee);
}

static int del_event_static(void *c, int flag)
{
    RedisConnection *conn = static_cast<RedisConnection *>(c);
    return conn->del_event(flag);
}

int RedisConnection::del_event(int flag)
{
    struct epoll_event ee = {};

    ee.events   = static_cast<uint32_t>(mask &= ~flag);
    ee.data.ptr = async_context;

    return epoll_ctl(epoll_fd, mask ? EPOLL_CTL_MOD : EPOLL_CTL_DEL, redis::redisGetFd(async_context), &ee);
}

void RedisConnection::cleanup()
{
    async_context = 0;
}

static void redisAddRead(void *ctx)
{
    add_event_static(ctx, EPOLLIN);
}

static void redisDelRead(void *ctx)
{
    del_event_static(ctx, EPOLLIN);
}

static void redisAddWrite(void *ctx)
{
    add_event_static(ctx, EPOLLOUT);
}

static void redisDelWrite(void *ctx)
{
    del_event_static(ctx, EPOLLOUT);
}

static void redisCleanup(void *ctx)
{
    RedisConnection *conn = static_cast<RedisConnection *>(ctx);
    return conn->cleanup();
}

static void authCallback_static(redisAsyncContext *c, void *r, void *privdata)
{
    RedisConnection *conn = static_cast<RedisConnection *>(privdata);
    conn->authCallback(c, r, privdata);
}

void RedisConnection::authCallback(struct redisAsyncContext *, void *r, void *)
{
    redisReply *reply = static_cast<redisReply *>(r);
    // DBG("got reply from redis");
    if (reply == nullptr) {
        ERROR("auth I/O error for connection '%s'", name.data());
    } else if (redis::isReplyError(reply)) {
        ERROR("auth error for connection '%s': %s", name.data(), redis::getReplyError(reply));
    } else {
        AmArg result;
        redisReply2Amarg(result, reply);
        DBG("redis connection '%s' auth success: %s", name.data(), AmArg::print(result).c_str());
        detect_role();
        return;
    }

    redis::redisAsyncDisconnect(async_context);
}

static void roleCallback_static(redisAsyncContext *c, void *r, void *privdata)
{
    RedisConnection *conn = static_cast<RedisConnection *>(privdata);
    conn->roleCallback(c, r, privdata);
}

void RedisConnection::roleCallback(struct redisAsyncContext *, void *r, void *)
{
    redisReply *reply = static_cast<redisReply *>(r);
    if (reply == nullptr) {
        ERROR("role I/O error for connection '%s'", name.data());
    } else if (redis::isReplyError(reply)) {
        ERROR("role error for connection '%s': %s", name.data(), redis::getReplyError(reply));
    } else {
        AmArg result;
        redisReply2Amarg(result, reply);
        DBG("redis connection '%s' role success: %s", name.data(), AmArg::print(result).c_str());
        master.set(result[0] == "master");
        connected.set(true);
        state_listener->on_connect(this);
        return;
    }

    redis::redisAsyncDisconnect(async_context);
}

int RedisConnection::init(int fd, const string &host, int port)
{
    this->host = host;
    this->port = port;
    epoll_fd   = fd;

    if (async_context)
        return 0;
    async_context = redis::redisAsyncConnect(host.c_str(), port);
    if (!async_context || redis::redisGetErrorNumber(async_context)) {
        CLASS_ERROR("%s redisAsyncContext: %s", name.c_str(), redis::redisGetError(async_context));
        return -1;
    }

    mask = 0;

    // init ctx
    redis::EpollCallbacks ev;
    ev.data     = this;
    ev.addRead  = redisAddRead;
    ev.delRead  = redisDelRead;
    ev.addWrite = redisAddWrite;
    ev.delWrite = redisDelWrite;
    ev.cleanup  = redisCleanup;
    redis::redisAsyncSetEpollCallbacks(async_context, ev);

    redis::redisAsyncSetConnectCallback(async_context, connectCallback_static);
    redis::redisAsyncSetDisconnectCallback(async_context, disconnectCallback_static);

    return 0;
}

void RedisConnection::set_auth_data(const string &password, const string &username)
{
    needAutorization = true;
    this->password   = password;
    this->username   = username;
}

void RedisConnection::connect()
{
    if (!connected.get()) {
        init(epoll_fd, host, port);
    }
}

int RedisConnection::reconnect(const std::string &host, int port)
{
    if (!connected.get()) {
        this->host = host;
        this->port = port;
        return 0;
    } else {
        redis::redisAsyncDisconnect(async_context);
    }

    return -1;
}

void RedisConnection::on_connect()
{
    if (needAutorization) {
        char *cmd;
        int   ret;
        if (username.empty())
            ret = redis::redisFormatCommand(&cmd, "AUTH %s", password.c_str());
        else
            ret = redis::redisFormatCommand(&cmd, "AUTH %s %s", username.c_str(), password.c_str());
        if (REDIS_OK != redis::redisAsyncFormattedCommand(async_context, &authCallback_static, this, cmd, ret)) {
            ERROR("failed send auth request");
        }
        free(cmd);
    } else {
        detect_role();
    }
}

void RedisConnection::on_disconnect()
{
    connected.set(false);
    state_listener->on_disconnect(this);
}

void RedisConnection::detect_role()
{
    char *cmd;
    int   ret;
    ret = redis::redisFormatCommand(&cmd, "ROLE");
    if (REDIS_OK != redis::redisAsyncFormattedCommand(async_context, &roleCallback_static, this, cmd, ret)) {
        ERROR("failed send role request");
    }
    free(cmd);
}

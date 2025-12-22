#include "RedisInstance.h"
#include "hiredis/hiredis.h"
#include "hiredis/async.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>
#include <log.h>
#include <AmUtils.h>

#include <queue>

using std::queue;

struct redisInstanceContext;

struct redisInstanceContext {
    RedisInstance *instance;
    union {
        redisAsyncContext *ac;
        redisContext      *c;
    } original;
    bool async;
};

RedisInstance *_redis_instance_ = 0;

static void connectCallback(const struct redisAsyncContext *ctx, int status)
{
    RedisInstance *instance = (RedisInstance *)ctx->data;
    instance->onConnect(status);
}

static void disconnectCallback(const struct redisAsyncContext *ctx, int status)
{
    RedisInstance *instance = (RedisInstance *)ctx->data;
    instance->onDisconnect(status);
}

int RedisInstance::redisAsyncSetConnectCallback(redisAsyncContext *ac, redisConnectCallback *fn)
{
    connect_callback = fn;
    return ::redisAsyncSetConnectCallback(ac, &connectCallback);
}

int RedisInstance::redisAsyncSetDisconnectCallback(redisAsyncContext *ac, redisDisconnectCallback *fn)
{
    disconnect_callback = fn;
    return ::redisAsyncSetDisconnectCallback(ac, &disconnectCallback);
}

RedisInstance *RedisInstance::clone(redisInstanceContext *async_context)
{
    RedisInstance *instance = new RedisInstance();
    instance->async_context = async_context;
    return instance;
}

namespace redis {

int redisAppendCommand(redisContext *c, const char *format, ...)
{
    va_list argptr;
    va_start(argptr, format);
    redisInstanceContext *context = (redisInstanceContext *)c;
    int                   ret     = ::redisAppendCommand(context->original.c, format, argptr);
    va_end(argptr);
    return ret;
}

int redisGetReply(redisContext *c, void **reply)
{
    redisInstanceContext *context = (redisInstanceContext *)c;
    return ::redisGetReply(context->original.c, reply);
}

bool isReplyError(redisReply *reply)
{
    return reply->type == REDIS_REPLY_ERROR;
}

bool isReplyStatus(redisReply *reply)
{
    return reply->type == REDIS_REPLY_STATUS;
}

char *getReplyError(redisReply *reply)
{
    return reply->str;
}

void freeReplyObject(redisContext *c, void *reply)
{
    ::freeReplyObject(reply);
}

int redisvFormatCommand(char **cmd, const char *fmt, va_list args)
{
    return ::redisvFormatCommand(cmd, fmt, args);
}

int redisFormatCommand(char **cmd, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int ret = redis::redisvFormatCommand(cmd, fmt, args);
    va_end(args);
    return ret;
}

long long redisFormatCommandArgv(char **target, int argc, const char **argv, const size_t *argvlen)
{
    return ::redisFormatCommandArgv(target, argc, argv, argvlen);
}

void redisFreeCommand(char *cmd)
{
    ::redisFreeCommand(cmd);
}

int redisvAsyncCommand(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, const char *format, ...)
{
    va_list argptr;
    va_start(argptr, format);
    redisInstanceContext *context = (redisInstanceContext *)ac;
    int                   ret     = ::redisvAsyncCommand(context->original.ac, fn, privdata, format, argptr);
    va_end(argptr);
    return ret;
}

int redisAsyncCommandArgv(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, int argc, const char **argv,
                          const size_t *argvlen)
{
    redisInstanceContext *context = (redisInstanceContext *)ac;
    return ::redisAsyncCommandArgv(context->original.ac, fn, privdata, argc, argv, argvlen);
}

int redisAsyncFormattedCommand(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, const char *cmd, size_t len)
{
    redisInstanceContext *context = (redisInstanceContext *)ac;
    return ::redisAsyncFormattedCommand(context->original.ac, fn, privdata, cmd, len);
}

redisAsyncContext *redisAsyncConnect(const char *ip, int port)
{
    if (!_redis_instance_)
        return 0;
    redisInstanceContext *context = (redisInstanceContext *)malloc(sizeof(redisInstanceContext));
    context->original.ac          = ::redisAsyncConnect(ip, port);
    context->async                = true;
    context->original.ac->data = context->instance = _redis_instance_->clone(context);
    return (redisAsyncContext *)context;
}

void redisAsyncDisconnect(redisAsyncContext *ac)
{
    redisInstanceContext *context = (redisInstanceContext *)ac;
    if (!context) {
        DBG("empty context");
        return;
    }

    if (!context->async) {
        ERROR("trying to free not async redis context");
        return;
    }

    ::redisAsyncDisconnect(context->original.ac);
}

redisContext *redisConnectWithTimeout(const char *ip, int port, const struct timeval tv)
{
    if (!_redis_instance_)
        return 0;
    redisInstanceContext *context = (redisInstanceContext *)malloc(sizeof(redisInstanceContext));
    context->original.c           = ::redisConnectWithTimeout(ip, port, tv);
    context->async                = false;
    context->instance             = _redis_instance_->clone(context);
    return (redisContext *)context;
}

redisContext *redisConnectUnixWithTimeout(const char *path, const struct timeval tv)
{
    if (!_redis_instance_)
        return 0;
    redisInstanceContext *context = (redisInstanceContext *)malloc(sizeof(redisInstanceContext));
    context->original.c           = ::redisConnectUnixWithTimeout(path, tv);
    context->async                = false;
    context->instance             = _redis_instance_->clone(context);
    return (redisContext *)context;
}

void redisFree(redisContext *ctx)
{
    redisInstanceContext *context = (redisInstanceContext *)ctx;
    if (context->async) {
        ERROR("trying freed async redis context");
        return;
    }
    ::redisFree(context->original.c);
    delete context->instance;
    free(context);
}

void redisFree(redisAsyncContext *ctx)
{
    redisInstanceContext *context = (redisInstanceContext *)ctx;
    if (!context->async) {
        ERROR("trying freed not async redis context");
        return;
    }
    delete context->instance;
    free(context);
}

char *redisGetError(void *c)
{
    redisInstanceContext *context = (redisInstanceContext *)c;
    return context->async ? context->original.ac->errstr : context->original.c->errstr;
}

int redisGetErrorNumber(void *c)
{
    redisInstanceContext *context = (redisInstanceContext *)c;
    return context->async ? context->original.ac->err : context->original.c->err;
}

int redisAsyncSetConnectCallback(redisAsyncContext *ac, redisConnectCallback *fn)
{
    redisInstanceContext *context = (redisInstanceContext *)ac;
    if (!context->async) {
        ERROR("using async function for not async redis context");
        return REDIS_ERR;
    }
    return context->instance->redisAsyncSetConnectCallback(context->original.ac, fn);
}

int redisAsyncSetDisconnectCallback(redisAsyncContext *ac, redisDisconnectCallback *fn)
{
    redisInstanceContext *context = (redisInstanceContext *)ac;
    if (!context->async) {
        ERROR("using async function for not async redis context");
        return REDIS_ERR;
    }
    return context->instance->redisAsyncSetDisconnectCallback(context->original.ac, fn);
}

void redisAsyncSetEpollCallbacks(redisAsyncContext *ac, EpollCallbacks ev)
{
    redisInstanceContext *context = (redisInstanceContext *)ac;
    if (!context->async) {
        ERROR("using async function for not async redis context");
        return;
    }
    context->original.ac->ev.data     = ev.data;
    context->original.ac->ev.addRead  = ev.addRead;
    context->original.ac->ev.addWrite = ev.addWrite;
    context->original.ac->ev.delRead  = ev.delRead;
    context->original.ac->ev.delWrite = ev.delWrite;
    context->original.ac->ev.cleanup  = ev.cleanup;
}

void *redisAsyncGetData(const redisAsyncContext *ctx)
{
    redisInstanceContext *context = (redisInstanceContext *)ctx;
    if (!context->async) {
        ERROR("using async function for not async redis context");
        return 0;
    }
    return context->original.ac->ev.data;
}

int redisGetFd(void *c)
{
    redisInstanceContext *context = (redisInstanceContext *)c;
    return context->original.c->fd;
}

void redisAsyncHandleRead(redisAsyncContext *ac)
{
    redisInstanceContext *context = (redisInstanceContext *)ac;
    ::redisAsyncHandleRead(context->original.ac);
}

void redisAsyncHandleWrite(redisAsyncContext *ac)
{
    redisInstanceContext *context = (redisInstanceContext *)ac;
    ::redisAsyncHandleWrite(context->original.ac);
}
} // namespace redis

void makeRedisInstance()
{
    if (!_redis_instance_)
        _redis_instance_ = new RedisInstance;
}

void freeRedisInstance()
{
    if (_redis_instance_) {
        delete _redis_instance_;
        _redis_instance_ = nullptr;
    }
}

void redisReply2Amarg(AmArg &a, redisReply *reply)
{
    switch (reply->type) {
    case REDIS_REPLY_ERROR:
        a.assertStruct();
        a["error"] = string(reply->str, reply->len);
        break;
    case REDIS_REPLY_STATUS:
        a.assertStruct();
        a["status"] = string(reply->str, reply->len);
        break;
    case REDIS_REPLY_NIL:     break;
    case REDIS_REPLY_STRING:  a = reply->str; break;
    case REDIS_REPLY_INTEGER: a = reply->integer; break;
    case REDIS_REPLY_ARRAY:
        a.assertArray();
        for (size_t i = 0; i < reply->elements; i++) {
            a.push(AmArg());
            redisReply2Amarg(a.back(), reply->element[i]);
        }
        break;
    default: ERROR("unexpected reply type: %d", reply->type);
    }
}

static bool isArgNumber(const AmArg &arg)
{
    return isArgInt(arg) || isArgLongLong(arg) || isArgDouble(arg);
}

void Amarg2redisReply(const AmArg &a, redisReply **r)
{
    *r = (redisReply *)malloc(sizeof(redisReply));
    memset(*r, 0, sizeof(redisReply));
    if (isArgNumber(a)) {
        (*r)->type    = REDIS_REPLY_INTEGER;
        (*r)->integer = a.asLongLong();
    } else if (isArgCStr(a)) {
        (*r)->type = REDIS_REPLY_STRING;
        (*r)->str  = strdup(a.asCStr());
        (*r)->len  = strlen(a.asCStr());
    } else if (isArgArray(a)) {
        (*r)->type     = REDIS_REPLY_ARRAY;
        (*r)->elements = a.size();
        (*r)->element  = (redisReply **)malloc(sizeof(redisReply *) * a.size());
        for (size_t i = 0; i < a.size(); i++)
            Amarg2redisReply(a[i], (*r)->element + i);
    } else if (isArgUndef(a)) {
        (*r)->type = REDIS_REPLY_NIL;
    } else {
        ERROR("incorrect AmArg for redisReply");
    }
}

static void checkReplyType(redisContext *ctx, redisReply *reply, int state, int expected,
                           const char *log) noexcept(false)
{
    if (state != REDIS_OK)
        throw GetReplyException(string(log) + ": redis::redisGetReply() != REDIS_OK", state);
    if (reply == NULL)
        throw GetReplyException(string(log) + ": reply == NULL", state);
    if (reply->type != expected) {
        if (reply->type == REDIS_REPLY_ERROR) {
            redis::freeReplyObject(ctx, reply);
            throw ReplyDataException(reply->str);
        }
        redis::freeReplyObject(ctx, reply);
        throw ReplyTypeException(string(log) + ": type not desired", reply->type);
    }
}

AmArg runMultiCommand(redisContext *ctx, const vector<string> &commands, const char *log) noexcept(false)
{
    redisReply *reply;
    AmArg       ret;
    redis::redisAppendCommand(ctx, "MULTI");
    for (auto &cmd : commands) {
        redis::redisAppendCommand(ctx, cmd.c_str());
    }
    redis::redisAppendCommand(ctx, "EXEC");

    int checkStatusNum = commands.size() + 1;

    for (int i = 0; i < checkStatusNum; i++) {
        int state = redis::redisGetReply(ctx, (void **)&reply);
        checkReplyType(ctx, reply, state, REDIS_REPLY_STATUS, log);
        redis::freeReplyObject(ctx, reply);
    }

    int state = redis::redisGetReply(ctx, (void **)&reply);
    checkReplyType(ctx, reply, state, REDIS_REPLY_ARRAY, log);
    redisReply2Amarg(ret, reply);
    redis::freeReplyObject(ctx, reply);
    return ret;
}

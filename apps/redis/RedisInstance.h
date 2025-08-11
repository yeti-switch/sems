#ifndef REDIS_INSTANCE_H
#define REDIS_INSTANCE_H

#include <time.h>
#include <AmArg.h>

struct redisContext;
struct redisInstanceContext;
struct redisAsyncContext;
struct redisReply;

#define REDIS_OK  0
#define REDIS_ERR -1

/* Connection callback prototypes */
typedef void(redisDisconnectCallback)(const struct redisAsyncContext *, int status);
typedef void(redisConnectCallback)(const struct redisAsyncContext *, int status);
typedef void(redisCallbackFn)(struct redisAsyncContext *, void *, void *);

namespace redis {
struct EpollCallbacks {
    void *data;

    /* Hooks that are called when the library expects to start
     * reading/writing. These functions should be idempotent. */
    void (*addRead)(void *privdata);
    void (*delRead)(void *privdata);
    void (*addWrite)(void *privdata);
    void (*delWrite)(void *privdata);
    void (*cleanup)(void *privdata);
};

redisContext      *redisConnectWithTimeout(const char *ip, int port, const struct timeval tv);
redisContext      *redisConnectUnixWithTimeout(const char *path, const struct timeval tv);
redisAsyncContext *redisAsyncConnect(const char *ip, int port);
void               redisAsyncDisconnect(redisAsyncContext *ac);
void               redisAsyncSetEpollCallbacks(redisAsyncContext *ac, EpollCallbacks ev);
void               redisFree(redisContext *ctx);
void               redisFree(redisAsyncContext *ctx);
void              *redisAsyncGetData(const redisAsyncContext *ctx);
int                redisGetFd(void *c);
char              *redisGetError(void *c);
int                redisGetErrorNumber(void *c);

int redisAsyncSetConnectCallback(redisAsyncContext *ac, redisConnectCallback *fn);
int redisAsyncSetDisconnectCallback(redisAsyncContext *ac, redisDisconnectCallback *fn);

void redisAsyncHandleRead(redisAsyncContext *ac);
void redisAsyncHandleWrite(redisAsyncContext *ac);

int redisAppendCommand(redisContext *c, const char *format, ...);
int redisGetReply(redisContext *c, void **reply);
int redisAsyncFormattedCommand(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, const char *cmd, size_t len);
int redisvAsyncCommand(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, const char *format, ...);
int redisAsyncCommandArgv(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, int argc, const char **argv,
                          const size_t *argvlen);

bool  isReplyError(redisReply *reply);
bool  isReplyStatus(redisReply *reply);
char *getReplyError(redisReply *reply);
void  freeReplyObject(redisContext *context, void *reply);

int       redisvFormatCommand(char **cmd, const char *fmt, va_list args);
int       redisFormatCommand(char **cmd, const char *fmt, ...);
long long redisFormatCommandArgv(char **target, int argc, const char **argv, const size_t *argvlen);
void      redisFreeCommand(char *cmd);
} // namespace redis

struct GetReplyException {
    std::string what;
    int         status;
    GetReplyException(std::string w, int s)
        : what(w)
        , status(s)
    {
    }
};

struct ReplyTypeException {
    std::string what;
    int         type;
    ReplyTypeException(std::string w, int t)
        : what(w)
        , type(t)
    {
    }
};

struct ReplyDataException {
    std::string what;
    ReplyDataException(std::string w)
        : what(w)
    {
    }
};

AmArg runMultiCommand(redisContext *ctx, const std::vector<std::string> &commands, const char *log) noexcept(false);
void  redisReply2Amarg(AmArg &a, redisReply *r);
void  Amarg2redisReply(const AmArg &a, redisReply **r);

void makeRedisInstance();
void freeRedisInstance();

class RedisInstance {
  protected:
    redisInstanceContext    *async_context;
    redisConnectCallback    *connect_callback;
    redisDisconnectCallback *disconnect_callback;

  public:
    RedisInstance()
        : async_context(0)
        , connect_callback(0)
        , disconnect_callback(0)
    {
    }
    virtual ~RedisInstance() {}

    void onConnect(int status) { connect_callback((redisAsyncContext *)async_context, status); }
    void onDisconnect(int status)
    {
        disconnect_callback((redisAsyncContext *)async_context, status);
        redis::redisFree((redisAsyncContext *)async_context);
    }

    virtual redisAsyncContext *redisAsyncConnect(const char *ip, int port)                                         = 0;
    virtual void               redisAsyncDisconnect(redisAsyncContext *ac)                                         = 0;
    virtual redisContext      *redisConnectWithTimeout(const char *ip, int port, const struct timeval tv)          = 0;
    virtual redisContext      *redisConnectUnixWithTimeout(const char *path, const struct timeval tv)              = 0;
    virtual int                redisAppendCommand(redisContext *c, const char *format, va_list list)               = 0;
    virtual int                redisAsyncSetConnectCallback(redisAsyncContext *ac, redisConnectCallback *fn)       = 0;
    virtual int                redisAsyncSetDisconnectCallback(redisAsyncContext *ac, redisDisconnectCallback *fn) = 0;
    virtual void               redisAsyncHandleRead(redisAsyncContext *ac)                                         = 0;
    virtual void               redisAsyncHandleWrite(redisAsyncContext *ac)                                        = 0;
    virtual int                redisGetReply(redisContext *c, void **reply)                                        = 0;
    virtual int  redisAsyncFormattedCommand(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, const char *cmd,
                                            size_t len)                                                            = 0;
    virtual int  redisAsyncCommandArgv(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, int argc,
                                       const char **argv, const size_t *argvlen)                                   = 0;
    virtual int  redisvAsyncCommand(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, const char *format,
                                    va_list argptr)                                                                = 0;
    virtual void freeReplyObject(void *reply)                                                                      = 0;
    virtual void redisFree(redisContext *ctx)                                                                      = 0;
    virtual RedisInstance *clone(redisInstanceContext *async_context)                                              = 0;
};

extern RedisInstance *_redis_instance_;

#endif /*REDIS_INSTANCE_H*/

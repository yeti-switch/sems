#include "RedisTestInstance.h"
#include "../RedisInstance.h"
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

static void connectCallback(const struct redisAsyncContext* ctx, int status) {
    RedisInstance* instance = (RedisInstance*)ctx->data;
    instance->onConnect(status);
}

static void disconnectCallback(const struct redisAsyncContext* ctx, int status) {
    RedisInstance* instance = (RedisInstance*)ctx->data;
    instance->onDisconnect(status);
}

class RedisTestConnection : public RedisInstance
{
    RedisTestServer* server;
    bool async_connected;
    struct Command{
        redisCallbackFn *replyfn;
        void* privdata;
        string command;
    };

    queue<Command> q;
public:
    RedisTestConnection(RedisTestServer* server)
    : server(server)
    , async_connected(false){}

    redisAsyncContext *redisAsyncConnect(const char *ip, int port) override
    {
        redisAsyncContext* ctx = (redisAsyncContext*)malloc(sizeof(redisAsyncContext));
        memset(ctx, 0, sizeof(redisAsyncContext));
        ctx->c.tcp.host = strdup(ip);
        ctx->c.tcp.source_addr = strdup(ip);
        ctx->c.tcp.port = port;
        ctx->c.connection_type = REDIS_CONN_TCP;
        ctx->c.fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        return ctx;
    }

    void redisAsyncDisconnect(redisAsyncContext *ac) override
    {
        if(ac->ev.cleanup)
            ac->ev.cleanup(ac->ev.data);
        redisFree(&ac->c);
        if(ac->onDisconnect)
            ac->onDisconnect(ac, REDIS_OK);
    }

    redisContext * redisConnectWithTimeout(const char* ip, int port, const struct timeval tv) override
    {
        redisContext* ctx = (redisContext*)malloc(sizeof(redisContext));
        memset(ctx, 0, sizeof(redisContext));
        ctx->tcp.host = strdup(ip);
        ctx->tcp.source_addr = strdup(ip);
        ctx->tcp.port = port;
        ctx->connection_type = REDIS_CONN_TCP;
#if HIREDIS_MAJOR > 0
        ctx->connect_timeout = (struct timeval*)malloc(sizeof(struct timeval));
        *ctx->connect_timeout = tv;

        ctx->command_timeout = (struct timeval*)malloc(sizeof(struct timeval));
        *ctx->command_timeout = tv;
#else
        ctx->timeout = (struct timeval*)malloc(sizeof(struct timeval));
        *ctx->timeout = tv;
#endif
        ctx->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        return ctx;
    }

    redisContext *redisConnectUnixWithTimeout(const char *path, const struct timeval tv) override
    {
        redisContext* ctx = (redisContext*)malloc(sizeof(redisContext));
        memset(ctx, 0, sizeof(redisContext));
        ctx->unix_sock.path = strdup(path);
        ctx->connection_type = REDIS_CONN_UNIX;
#if HIREDIS_MAJOR > 0
        ctx->connect_timeout = (struct timeval*)malloc(sizeof(struct timeval));
        *ctx->connect_timeout = tv;

        ctx->command_timeout = (struct timeval*)malloc(sizeof(struct timeval));
        *ctx->command_timeout = tv;
#else
        ctx->timeout = (struct timeval*)malloc(sizeof(struct timeval));
        *ctx->timeout = tv;
#endif
        ctx->fd = socket(AF_UNIX, SOCK_STREAM, 0);
        return ctx;
    }

    void redisFree(redisContext* ctx) override
    {
        if(ctx->tcp.host) free(ctx->tcp.host);
        if(ctx->tcp.source_addr) free(ctx->tcp.source_addr);
        if(ctx->unix_sock.path) free(ctx->unix_sock.path);
#if HIREDIS_MAJOR > 0
        if(ctx->connect_timeout) free(ctx->connect_timeout);
        if(ctx->command_timeout) free(ctx->command_timeout);
#else
        if(ctx->timeout) free(ctx->timeout);
#endif
        close(ctx->fd);
        free(ctx);
    }

    int redisAsyncSetConnectCallback(redisAsyncContext *ac, redisConnectCallback *fn) override
    {
        connect_callback = fn;
        ac->onConnect = &connectCallback;
        if(ac->ev.addWrite) {
            ac->ev.addWrite(ac->ev.data);
        } else {
            ERROR("absent event function in redis context");
        }
        return REDIS_OK;
    }

    int redisAsyncSetDisconnectCallback(redisAsyncContext *ac, redisDisconnectCallback *fn) override
    {
        disconnect_callback = fn;
        ac->onDisconnect = &disconnectCallback;
        return REDIS_OK;
    }

    void redisAsyncHandleRead(redisAsyncContext *) override {}
    void redisAsyncHandleWrite(redisAsyncContext *ac) override
    {
        if(!async_connected && ac->onConnect) {
            async_connected = true;
            ac->onConnect(ac, REDIS_OK);

            if(q.empty()) {
                if(ac->ev.delWrite) {
                    ac->ev.delWrite(ac->ev.data);
                } else {
                    ERROR("absent event function in redis context");
                }
            }

        } else {
            redisReply* reply;
            Command cmd = q.front();
            redisGetReply(&ac->c, (void**)&reply);
            if(cmd.replyfn)
                cmd.replyfn(ac, reply, cmd.privdata);
            freeReplyObject(reply);
            if(q.empty()) {
                if(ac->ev.delWrite) {
                    ac->ev.delWrite(ac->ev.data);
                } else {
                    ERROR("absent event function in redis context");
                }
            }
        }
    }

    int redisAsyncFormattedCommand(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata_, const char *cmd, size_t len) override
    {
        if(ac->ev.addWrite)
           ac->ev.addWrite(ac->ev.data);
        Command current;
        current.replyfn = fn;
        current.privdata = privdata_;
        current.command = string(cmd, len);
        q.push(current);
        return REDIS_OK;
    }

    int redisAsyncCommandArgv(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, int argc, const char **argv, const size_t *argvlen) override
    {
        return REDIS_ERR;
    }

    int redisvAsyncCommand(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, const char* format, va_list argptr) override
    {
        return REDIS_ERR;
    }

    int redisAppendCommand(redisContext* , const char* format, va_list argptr) override
    {
        Command current;
        current.replyfn = 0;
        current.privdata = 0;
        char* cmd;
        redisvFormatCommand(&cmd, format, argptr);
        current.command = cmd;
        q.push(current);
        redisFreeCommand(cmd);
        return REDIS_OK;
    }

    int redisGetReply(redisContext* c, void ** reply) override
    {
        Command& cmd = q.front();

        AmArg r;
        if(server) {
            server->getResponse(cmd.command, r);
        }

        Amarg2redisReply(r, (redisReply**)reply);
        //INFO("redisGetReply type %d", (*(redisReply**)reply)->type);
        redisReply* _reply = (redisReply*)*reply;
        if(server && server->getStatus(cmd.command) == REDIS_REPLY_STATUS && _reply->type == REDIS_REPLY_NIL) {
            q.pop();
            _reply->type = REDIS_REPLY_STATUS;
            return REDIS_OK;
        } else if(server && _reply->type != server->getStatus(cmd.command)) {
            q.pop();
            _reply->type = REDIS_REPLY_ERROR;
            c->err = REDIS_REPLY_ERROR;
            return REDIS_REPLY_ERROR;
        }
        q.pop();
        return REDIS_OK;
    }

    void freeReplyObject(void *reply) override
    {
        if(!reply) return;
        redisReply* _reply = (redisReply*)reply;
        if(_reply->str) free(_reply->str);
        if(_reply->element) {
            for(size_t i = 0; i < _reply->elements; i++)
                freeReplyObject(_reply->element[i]);
            free(_reply->element);
        }
        free(reply);
    }

    RedisInstance* clone(redisInstanceContext* async_context) override {
        RedisTestConnection* instance = new RedisTestConnection(server);
        instance->async_context = async_context;
        return instance;
    }
};

void makeRedisInstance(RedisTestServer* server_)
{
    if(!_redis_instance_)
        _redis_instance_ = new RedisTestConnection(server_);
}


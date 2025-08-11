#ifndef REDIS_CONNECTION_POOL_H
#define REDIS_CONNECTION_POOL_H

#include <AmArg.h>
#include <AmEventFdQueue.h>
#include <AmSessionContainer.h>
#include <RedisApi.h>

#include "RedisConnection.h"

class RedisConnectionPool;

struct RedisReplyCtx {
    RedisConnection     *c;
    RedisConnectionPool *pool;

    bool                      persistent_ctx;
    string                    conn_id;
    string                    session_id;
    std::unique_ptr<AmObject> user_data;
    int                       user_type_id;

    RedisReplyCtx(RedisConnection *c, RedisRequest &r)
        : c(c)
        , pool(nullptr)
        , persistent_ctx(r.persistent_ctx)
        , conn_id(std::move(r.conn_id))
        , session_id(std::move(r.session_id))
        , user_data(std::move(r.user_data))
        , user_type_id(r.user_type_id)
    {
    }
    RedisReplyCtx(RedisConnection *c, AmObject *user_data, RedisConnectionPool *pool)
        : c(c)
        , pool(pool)
        , persistent_ctx()
        , conn_id()
        , session_id()
        , user_data(user_data)
        , user_type_id()
    {
    }

    //~RedisReplyCtx() { CLASS_DBG("~RedisReplyCtx()"); }
};

class RedisConnectionPool : public AmThread,
                            public AmEventFdQueue,
                            public AmEventHandler,
                            public RedisConnectionStateListener {
    int         epoll_fd;
    const char *name;
    string      queue_name;

    AmEventFd         stop_event;
    AmCondition<bool> stopped;

    AmTimerFd reconnect_timer;
    AmTimerFd retry_reqs_timer;

    std::list<RedisReplyCtx *>   persistent_reply_contexts;
    std::list<RedisConnection *> connections;

  protected:
    void run() override;
    void on_stop() override;

    int init();

    void         process(AmEvent *ev) override;
    virtual void process_request_event(RedisRequest &event, RedisConnection *c);
    virtual void process_internal_request(RedisConnection *c, AmObject *user_data, const char *fmt...);
    virtual void process_internal_vrequest(RedisConnection *c, AmObject *user_data, const char *fmt, va_list args);
    void         process_stop_event();
    void         reconnect();
    void         init_retry_reqs_timer(unsigned int timeout_ms);
    virtual void on_retry_reqs_timer() {};

  public:
    RedisConnectionPool(const char *name, const string &queue_name);
    virtual ~RedisConnectionPool();

    RedisConnection *addConnection(const string &name, const string &host, int port);
    void             removeConnection(RedisConnection *c);
    string           get_queue_name() { return queue_name; }
    virtual void process_internal_reply(RedisConnection *c, int result, const AmObject *user_data, const AmArg &data) {
    };
};

#endif /*REDIS_CONNECTION_POOL_H*/

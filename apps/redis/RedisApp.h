#pragma once
#include <AmApi.h>
#include <AmEventFdQueue.h>
#include <AmStatistics.h>
#include <RedisApi.h>

#include "RedisConnectionPool.h"
#include "RedisAppConfig.h"
#include "unit_tests/RedisTest.h"

#include <string>
#include <vector>
#include <map>

using std::string;
using std::vector;
using std::queue;
using std::map;
using std::chrono::milliseconds;

class RedisApp
  : public RedisConnectionPool,
    public Configurable
{
  private:
    friend RedisTest;
    static RedisApp* _instance;

    int max_batch_size;
    milliseconds batch_timeout;
    int max_queue_size;

    struct Connection {
        string id;
        RedisConnectionInfo info;
        string session_id;
        RedisConnection *redis_conn;
        AtomicCounter& connected_stat;
        AtomicCounter& retry_reqs_count_stat;
        AtomicCounter& dropped_reqs_count_stat;

        Connection(const string &id, const RedisConnectionInfo &info,
            const string &session_id, RedisConnection *redis_conn)
          : id(id), info(info), session_id(session_id), redis_conn(redis_conn),
            connected_stat(stat_group(Gauge, MOD_NAME, "connected")
                .addAtomicCounter().addLabel("connection", id)),
            retry_reqs_count_stat(stat_group(Gauge, MOD_NAME, "retry_reqs_count")
                .addAtomicCounter().addLabel("connection", id)),
            dropped_reqs_count_stat(stat_group(Counter, MOD_NAME, "dropped_reqs_count")
                .addAtomicCounter().addLabel("connection", id))
        {}

        void on_connect();
        void on_disconnect();
        bool is_connected();
        void on_script_loaded(const RedisScript& script, const char *hash);
        bool is_scripts_loaded();
        void set_script_hash(const RedisScript& script, const char *hash);
        void load_scripts();
        void drop_data();
        void post_conn_state(RedisConnectionState::RedisConnState state);
    };
    vector<Connection> connections;
    map<Connection*, queue<RedisRequest>> retry_reqs;
    Connection* find_conn(const string& id);
    Connection* find_conn(const RedisConnection* c);

  protected:
    friend class RedisAppFactory;
    int onLoad();
    void process(AmEvent* ev) override;
    void process_redis_add_connection_event(RedisAddConnection &event);
    void process_redis_request_event(RedisRequest &event);
    void process_internal_reply(const RedisConnection *c, int result, const AmObject *user_data, const AmArg &data) override;
    void process_retry_reqs(Connection *conn);
    void on_connect(RedisConnection* conn) override;
    void on_disconnect(RedisConnection* conn) override;
    int configure(cfg_t* cfg) override;
    void on_retry_reqs_timer() override;

  public:
    RedisApp();
    virtual ~RedisApp();

    static RedisApp* instance();
    static void dispose();
};

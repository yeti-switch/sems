#include "RedisTest.h"
#include "../RedisInstance.h"
#include "../RedisConnection.h"
#include "../RedisConnectionPool.h"

#include <hiredis/hiredis.h>

TEST_F(RedisTest, RedisFormatTest)
{
    char *cmd, *cmd1;
    redis::redisFormatCommand(&cmd,"HSET %s %d %d","r:471",8,0);
    ::redisFormatCommand(&cmd1,"HSET %s %d %d","r:471",8,0);
    ASSERT_FALSE(strcmp(cmd, cmd1));
    redis::redisFreeCommand(cmd);
    ::redisFreeCommand(cmd1);
}

TEST_F(RedisTest, RedisSimpleTest)
{
    timeval timeout = { DEFAULT_REDIS_TIMEOUT_MSEC, 0 };
    redisContext* ctx = redis::redisConnectWithTimeout(
        redis_test::instance()->settings.host.c_str(),
        redis_test::instance()->settings.port, timeout);
    ASSERT_TRUE(ctx);
    ASSERT_FALSE(redis::redisGetErrorNumber(ctx));
    ASSERT_FALSE(redis::redisAppendCommand(ctx, "HSET %s %d %d","r:471",8,0));
    redisReply* r;
    ASSERT_FALSE(redis::redisGetReply(ctx, (void**)&r));
    redis::freeReplyObject(ctx, r);
    redis::redisFree(ctx);
}

class TestRedisConnection
  : public RedisConnectionPool
{
    AmCondition<bool> gotreply;
    AmArg result;
    RedisConnection* conn;
    RedisReply::result_type rstatus;

  public:
    TestRedisConnection()
      : RedisConnectionPool("test", "regTest"),
        gotreply(false),
        rstatus(RedisReply::SuccessReply)
    {}
    ~TestRedisConnection() {}

    void process_internal_reply(const RedisConnection *c, int result,
        const AmObject *user_data, const AmArg &data) override {
        gotreply.set(true);
        this->result = data;
        rstatus = static_cast<RedisReply::result_type>(result);
    }

    int init(const string& host, int port) {
        int ret = RedisConnectionPool::init();
        conn = addConnection(host, port);
        if(ret || !conn) return -1;
        return 0;
    }

    bool is_connected() {return conn->is_connected(); }
    bool wait_connected() { return conn->wait_connected(); }
    bool is_gotreply() {return gotreply.get(); }
    bool wait_reply() { return gotreply.wait_for_to(500); }
    void drop_gotreply() { gotreply.set(false); }

    RedisReply::result_type get_result_type() { return rstatus; }
    AmArg& get_result() { return result; }
    RedisConnection* get_connection() { return conn; }

    void process_request(RedisConnection *c, AmObject *user_data, const char *fmt...) {
        va_list args;
        va_start(args, fmt);
        process_internal_vrequest(c, user_data, fmt, args);
        va_end(args);
    }
};

TEST_F(RedisTest, RedisConnectionTest)
{
    TestRedisConnection conn;
    conn.init(redis_test::instance()->settings.host.c_str(),
              redis_test::instance()->settings.port);
    conn.start();

    time_t time_ = time(0);
    while(!conn.wait_connected()) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    char *cmd;
    redis::redisFormatCommand(&cmd,"HSET %s %d %d","r:471",8,0);
    test_server->addFormattedCommandResponse(cmd, REDIS_REPLY_NIL, AmArg());
    conn.process_request(conn.get_connection(), nullptr, "HSET %s %d %d","r:471",8,0);
    delete cmd; cmd = nullptr;

    time_ = time(0);
    while(!conn.wait_reply()){
        ASSERT_FALSE(time(0) - time_ > 30);
    }
    conn.drop_gotreply();

    redis::redisFormatCommand(&cmd,"HGET %s %d", "r:471", 8);

    AmArg res;
    res.assertArray();
    res.push("0");
    test_server->addFormattedCommandResponse(cmd, REDIS_REPLY_ARRAY, res);
    conn.process_request(conn.get_connection(), nullptr, "HGET %s %d", "r:471", 8);
    delete cmd; cmd = nullptr;

    time_ = time(0);
    while(!conn.wait_reply()){
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    INFO("conn.result %s", AmArg::print(conn.get_result()).c_str());
    ASSERT_EQ(conn.get_result_type(), RedisReply::SuccessReply);

    conn.stop(true);
}

TEST_F(RedisTest, RedisConnectionTest1)
{
    TestRedisConnection conn;
    conn.init(redis_test::instance()->settings.host.c_str(),
              redis_test::instance()->settings.port);
    conn.start();

    time_t time_ = time(0);
    while(!conn.wait_connected()) {
        ASSERT_FALSE(time(0) - time_ > 3);
    }

    char *cmd;
    redis::redisFormatCommand(&cmd,"HSET %s %d %d","r:471",8,0);
    test_server->addFormattedCommandResponse(cmd, REDIS_REPLY_NIL, AmArg());
    conn.process_request(conn.get_connection(), nullptr, "HSET %s %d %d","r:471",8,0);
    delete cmd; cmd = nullptr;

    redis::redisFormatCommand(&cmd,"HGET %s %d", "r:471", 8);

    AmArg res;
    res.assertArray();
    res.push("0");
    test_server->addFormattedCommandResponse(cmd, REDIS_REPLY_ARRAY, res);
    conn.process_request(conn.get_connection(), nullptr, "HGET %s %d", "r:471", 8);
    delete cmd; cmd = nullptr;

    for(int i = 0; i < 2; i++) {
        time_ = time(0);
        while(!conn.wait_reply()){
            ASSERT_FALSE(time(0) - time_ > 3);
        }
    }

    INFO("conn.result %s", AmArg::print(conn.get_result()).c_str());
    ASSERT_EQ(conn.get_result_type(), RedisReply::SuccessReply);

    conn.stop(true);
}

TEST_F(RedisTest, RedisMultiTest)
{
    timeval timeout = { DEFAULT_REDIS_TIMEOUT_MSEC, 0 };
    redisContext* ctx = redis::redisConnectWithTimeout(
        redis_test::instance()->settings.host.c_str(),
        redis_test::instance()->settings.port, timeout);
    ASSERT_TRUE(ctx);
    ASSERT_FALSE(redis::redisGetErrorNumber(ctx));
    vector<string> commands;
    commands.push_back("HSET r:471 8 0");
    commands.push_back("HGET r:471 8");
    test_server->addCommandResponse("MULTI", REDIS_REPLY_STATUS, AmArg());
    test_server->addCommandResponse(commands[0], REDIS_REPLY_STATUS, AmArg());
    test_server->addCommandResponse(commands[1], REDIS_REPLY_STATUS, AmArg());
    AmArg res;
    res.assertArray();
    res[0] = 0;
    res[1] = "0";
    test_server->addCommandResponse("EXEC", REDIS_REPLY_ARRAY, res);
    AmArg ret = runMultiCommand(ctx, commands, "HSET-HGET");
    redis::redisFree(ctx);
}

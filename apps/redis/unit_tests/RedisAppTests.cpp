#include "RedisTest.h"
#include "../RedisApp.h"
#include "RedisTestClient.h"

#include <RedisApi.h>
#include <AmSessionContainer.h>

#include <hiredis/read.h>

/* Helpers */

#define session_container        AmSessionContainer::instance()
#define host                     redis_test::instance()->settings.host.c_str()
#define port                     redis_test::instance()->settings.port
#define post_to_redis_app(event) session_container->postEvent(REDIS_APP_QUEUE, event);


/* Tests */

TEST_F(RedisTest, RedisAppConnect)
{
    RedisTestClient redis_client;
    redis_client.start();

    {
        post_to_redis_app(new RedisAddConnection(REDIS_TEST_CLIENT_QUEUE, "RedisAppConnect1",
                                                 RedisConnectionInfo(host, port, RedisMaster)));
        wait_for_cond(redis_client.connected);
        redis_client.reset();
    }

    stop(redis_client);
}

TEST_F(RedisTest, RedisAppConnectScript1)
{
    RedisTestClient redis_client;
    redis_client.start();

    {
        RedisScript script("test_script_1", "apps/redis/unit_tests/etc/test_script_1.lua");
        post_to_redis_app(new RedisAddConnection(REDIS_TEST_CLIENT_QUEUE, "RedisAppConnectScript1",
                                                 RedisConnectionInfo(host, port, RedisMaster, "", "", { script })));
        wait_for_cond(redis_client.connected);

        GTEST_ASSERT_EQ(redis_client.conn_info.scripts.size(), 1);
        GTEST_ASSERT_EQ(redis_client.conn_info.scripts.front().hash.length() > 0, true);

        redis_client.reset();
    }

    stop(redis_client);
}

TEST_F(RedisTest, RedisAppConnectScript2)
{
    RedisTestClient redis_client;
    redis_client.start();

    {
        RedisScript script1("test_script_1", "apps/redis/unit_tests/etc/test_script_1.lua");
        RedisScript script2("test_script_2", "apps/redis/unit_tests/etc/test_script_2.lua");
        RedisScript script3("test_script_3", "apps/redis/unit_tests/etc/test_script_3.lua");
        RedisScript script4("test_script_4", "apps/redis/unit_tests/etc/test_script_4.lua");
        post_to_redis_app(new RedisAddConnection(
            REDIS_TEST_CLIENT_QUEUE, "RedisAppConnectScript2",
            RedisConnectionInfo(host, port, RedisMaster, "", "", { script1, script2, script3, script4 })));
        wait_for_cond(redis_client.connected);

        GTEST_ASSERT_EQ(redis_client.conn_info.scripts.size(), 4);
        for (const auto &s : redis_client.conn_info.scripts)
            GTEST_ASSERT_EQ(s.hash.length() > 0, true);

        redis_client.reset();
    }

    // "wrong_path_script" - works with real db
    /*{
        RedisScript wrong_path_script("script", "/wrong/path.lua");
        post_to_redis_app(new RedisAddConnection(TEST_REDIS_APP_CLIENT_QUEUE, "RedisAppConnectScript3",
            RedisConnectionInfo(host, port, "", "", {wrong_path_script})));
        wait_for_cond(redis_client.disconnected);
        reset(redis_client);
    }*/

    stop(redis_client);
}

TEST_F(RedisTest, RedisAppRequest1)
{
    RedisTestClient redis_client;
    redis_client.start();

    {
        const string conn_id = "RedisAppRequest1";
        post_to_redis_app(
            new RedisAddConnection(REDIS_TEST_CLIENT_QUEUE, conn_id, RedisConnectionInfo(host, port, RedisMaster)));
        wait_for_cond(redis_client.connected);

        // del
        {
            post_to_redis_app(new RedisRequest(REDIS_TEST_CLIENT_QUEUE, conn_id, { "HDEL", "myhash", "field1" }));
            wait_for_cond(redis_client.reply_available);
            GTEST_ASSERT_EQ(redis_client.reply_conn_id, conn_id);
            // GTEST_ASSERT_EQ(redis_client.reply_data.print(), "0"); can be 1 or 0
        }

        // set string
        {
            // set
            post_to_redis_app(
                new RedisRequest(REDIS_TEST_CLIENT_QUEUE, conn_id, { "HSET", "myhash", "field1", "\"Hello\"" }));
            wait_for_cond(redis_client.reply_available);
            GTEST_ASSERT_EQ(redis_client.reply_conn_id, conn_id);
            GTEST_ASSERT_EQ(redis_client.reply_data.print(), "1");

            // get
            post_to_redis_app(new RedisRequest(REDIS_TEST_CLIENT_QUEUE, conn_id, { "HGET", "myhash", "field1" }));
            wait_for_cond(redis_client.reply_available);
            GTEST_ASSERT_EQ(redis_client.reply_conn_id, conn_id);
            GTEST_ASSERT_EQ(redis_client.reply_data.print(), "'\"Hello\"'");


            // del
            post_to_redis_app(new RedisRequest(REDIS_TEST_CLIENT_QUEUE, conn_id, { "HDEL", "myhash", "field1" }));
            wait_for_cond(redis_client.reply_available);
            GTEST_ASSERT_EQ(redis_client.reply_conn_id, conn_id);
            GTEST_ASSERT_EQ(redis_client.reply_data.print(), "1");
        }

        // set number
        {
            // set
            post_to_redis_app(new RedisRequest(REDIS_TEST_CLIENT_QUEUE, conn_id, { "HSET", "myhash", "field1", 5 }));
            wait_for_cond(redis_client.reply_available);
            GTEST_ASSERT_EQ(redis_client.reply_conn_id, conn_id);
            GTEST_ASSERT_EQ(redis_client.reply_data.print(), "1");

            // get
            post_to_redis_app(new RedisRequest(REDIS_TEST_CLIENT_QUEUE, conn_id, { "HGET", "myhash", "field1" }));
            wait_for_cond(redis_client.reply_available);
            GTEST_ASSERT_EQ(redis_client.reply_conn_id, conn_id);
            GTEST_ASSERT_EQ(redis_client.reply_data.print(), "'5'");

            // del
            post_to_redis_app(new RedisRequest(REDIS_TEST_CLIENT_QUEUE, conn_id, { "HDEL", "myhash", "field1" }));
            wait_for_cond(redis_client.reply_available);
            GTEST_ASSERT_EQ(redis_client.reply_conn_id, conn_id);
            GTEST_ASSERT_EQ(redis_client.reply_data.print(), "1");
        }

        // set float
        {
            // set
            post_to_redis_app(new RedisRequest(REDIS_TEST_CLIENT_QUEUE, conn_id, { "HSET", "myhash", "field1", 5.3 }));
            wait_for_cond(redis_client.reply_available);
            GTEST_ASSERT_EQ(redis_client.reply_conn_id, conn_id);
            GTEST_ASSERT_EQ(redis_client.reply_data.print(), "1");

            // get
            post_to_redis_app(new RedisRequest(REDIS_TEST_CLIENT_QUEUE, conn_id, { "HGET", "myhash", "field1" }));
            wait_for_cond(redis_client.reply_available);
            GTEST_ASSERT_EQ(redis_client.reply_conn_id, conn_id);
            GTEST_ASSERT_EQ(redis_client.reply_data.print(), "'5.3'");

            // del
            post_to_redis_app(new RedisRequest(REDIS_TEST_CLIENT_QUEUE, conn_id, { "HDEL", "myhash", "field1" }));
            wait_for_cond(redis_client.reply_available);
            GTEST_ASSERT_EQ(redis_client.reply_conn_id, conn_id);
            GTEST_ASSERT_EQ(redis_client.reply_data.print(), "1");
        }
    }

    stop(redis_client);
}

TEST_F(RedisTest, RedisAppRequest2)
{
    RedisTestClient redis_client;
    redis_client.start();

    // user_data, user_type_id
    {
        const string conn_id = "RedisAppRequest2";
        post_to_redis_app(
            new RedisAddConnection(REDIS_TEST_CLIENT_QUEUE, conn_id, RedisConnectionInfo(host, port, RedisMaster)));
        wait_for_cond(redis_client.connected);

        // set
        TestUserData user_data;
        const int    user_type_id = 1234;
        user_data.value           = "set hello user data";
        post_to_redis_app(new RedisRequest(REDIS_TEST_CLIENT_QUEUE, conn_id,
                                           { "HSET", "myhash", "field1", "\"Hello\"" }, &user_data, user_type_id));
        wait_for_cond(redis_client.reply_available);
        GTEST_ASSERT_EQ(redis_client.reply_conn_id, conn_id);
        GTEST_ASSERT_EQ(redis_client.reply_data.print(), "1");
        ASSERT_TRUE(dynamic_cast<TestUserData *>(redis_client.reply_user_data));
        GTEST_ASSERT_EQ(dynamic_cast<TestUserData *>(redis_client.reply_user_data)->value, "set hello user data");
        GTEST_ASSERT_EQ(redis_client.reply_user_type_id, user_type_id);

        // del
        post_to_redis_app(new RedisRequest(REDIS_TEST_CLIENT_QUEUE, conn_id, { "HDEL", "myhash", "field1" }));
        wait_for_cond(redis_client.reply_available);
        GTEST_ASSERT_EQ(redis_client.reply_conn_id, conn_id);
        GTEST_ASSERT_EQ(redis_client.reply_data.print(), "1");
    }

    stop(redis_client);
}

TEST_F(RedisTest, RedisAppRequest3)
{
    RedisTestClient redis_client;
    redis_client.start();

    // waiting_reqs
    {
        const string conn_id = "RedisAppRequest3";
        post_to_redis_app(
            new RedisAddConnection(REDIS_TEST_CLIENT_QUEUE, conn_id, RedisConnectionInfo(host, port, RedisMaster)));

        // don't wait for connection, request will be placed on waiting_reqs queue
        // wait_for_cond(redis_client.connected);

        // set
        post_to_redis_app(
            new RedisRequest(REDIS_TEST_CLIENT_QUEUE, conn_id, { "HSET", "myhash", "field1", "\"Hello\"" }));

        // redis_client is still not connected
        GTEST_ASSERT_FALSE(redis_client.connected.get());

        wait_for_cond(redis_client.reply_available);
        GTEST_ASSERT_EQ(redis_client.reply_conn_id, conn_id);
        GTEST_ASSERT_EQ(redis_client.reply_data.print(), "1");

        // check is connected after request is done
        wait_for_cond(redis_client.connected);

        // del
        post_to_redis_app(new RedisRequest(REDIS_TEST_CLIENT_QUEUE, conn_id, { "HDEL", "myhash", "field1" }));
        wait_for_cond(redis_client.reply_available);
        GTEST_ASSERT_EQ(redis_client.reply_conn_id, conn_id);
        GTEST_ASSERT_EQ(redis_client.reply_data.print(), "1");
    }

    stop(redis_client);
}

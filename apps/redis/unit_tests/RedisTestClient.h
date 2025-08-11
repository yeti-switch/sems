#pragma once

#include <TestClient.h>
#include <ampi/RedisApi.h>

#define REDIS_TEST_CLIENT_QUEUE "redis_test_client_queue"

class RedisTestClient : public TestClient {
  protected:
    void process(AmEvent *e) override;

  public:
    RedisTestClient();
    void reset() override;

    AmCondition<bool>   connected;
    AmCondition<bool>   disconnected;
    RedisConnectionInfo conn_info;
    string              reply_conn_id;
    int                 reply_user_type_id;
};

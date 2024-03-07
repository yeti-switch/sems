#include "RedisTestClient.h"

RedisTestClient::RedisTestClient()
  : TestClient(REDIS_TEST_CLIENT_QUEUE)
{}

void RedisTestClient::process(AmEvent* event)
{
    switch(event->event_id) {
        case RedisEvent::ConnectionState:
            if(auto e = dynamic_cast<RedisConnectionState*>(event)) {
                conn_info = e->info;
                if(e->state == RedisConnectionState::Connected)
                    connected.set(true);
                else if(e->state == RedisConnectionState::Disconnected)
                    disconnected.set(true);
                return;
            }
            break;
        case RedisEvent::Reply:
            if(auto e = dynamic_cast<RedisReply*>(event)) {
                if(e->result == RedisReply::SuccessReply) {
                    reply_data = e->data;
                    reply_user_data = e->user_data.release();
                    reply_conn_id = e->conn_id;
                    reply_user_type_id = e->user_type_id;
                    reply_available.set(true);
                }
                return;
            }
            break;
    }

    TestClient::process(event);
}

void RedisTestClient::reset() {
    TestClient::reset();
    connected.set(false);
    disconnected.set(false);
    conn_info = RedisConnectionInfo();
    reply_conn_id = "";
    reply_user_type_id = 0;
}

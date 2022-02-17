#include "PGHandler.h"

TEST_F(PostgresqlTest, ConnectionTest)
{
    PGHandler handler;
    IPGConnection* conn = PolicyFactory::instance()->createConnection(POOL_ADDRESS_STR, &handler);
    ASSERT_EQ(handler.cur_state, PGHandler::DISCONNECTED);
    ASSERT_EQ(handler.count, 0);
    ASSERT_EQ(handler.dis_count, 0);
    conn->reset();
    while(conn->getStatus() != CONNECTION_OK) {
        if(handler.check() < 1) return;
    }
    ASSERT_EQ(handler.cur_state, PGHandler::CONNECTED);
    int conn_count = handler.count;
    int conn_discount = handler.dis_count;
    ASSERT_TRUE(handler.count > 0);
    ASSERT_TRUE(handler.dis_count >= 0);

    conn->reset();
    ASSERT_TRUE(handler.count == conn_count);
    ASSERT_TRUE(handler.dis_count > conn_discount);
    while(conn->getStatus() != CONNECTION_OK) {
        if(handler.check() < 1) return;
    }
    ASSERT_EQ(handler.cur_state, PGHandler::CONNECTED);
    ASSERT_TRUE(handler.count > conn_count);

    delete conn;
}
/*
TEST_F(PostgresqlTest, ReconnectTest)
{
    PGHandler handler;
    std::string conn_str(POOL_ADDRESS_STR);
    IPGConnection *conn = PolicyFactory::instance()->createConnection(conn_str, &handler);
    conn->reset();
    while(conn->getStatus() != CONNECTION_OK) {
        handler.check();
    }
    handler.cur_state = PGHandler::DISCONNECTED;

    while(handler.cur_state != PGHandler::CONNECTED) {
        handler.check();
        sleep(1);
    }

    delete conn;
}*/

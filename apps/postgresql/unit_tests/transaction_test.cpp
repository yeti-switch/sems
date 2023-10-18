#include "PGHandler.h"

#include <ampi/PostgreSqlAPI.h>
#include "../pqtypes-int.h"

#include "../query/Query.h"
#include "../query/QueryChain.h"

#include "../trans/NonTransaction.h"
#include "../trans/DbTransaction.h"
#include "../trans/PreparedTransaction.h"

TEST_F(PostgresqlTest, NonTransactionSimpleTest)
{
    PGHandler handler;
    std::string conn_str(address);
    Connection *conn = PolicyFactory::instance()->createConnection(conn_str, conn_str, &handler);
    conn->reset();
    NonTransaction pg_backend(&handler);
    pg_backend.exec(new Query("SELECT pg_backend_pid()", false));
    conn->runTransaction(&pg_backend);
    while(pg_backend.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    ASSERT_EQ(handler.cur_state, PGHandler::FINISH);
    handler.cur_state = PGHandler::CONNECTED;

    NonTransaction show_tables(&handler);
    show_tables.exec(new Query("SHOW TABLES", false));
    conn->runTransaction(&show_tables);
    while(show_tables.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    ASSERT_EQ(handler.cur_state, PGHandler::FINISH);

    delete conn;
}

TEST_F(PostgresqlTest, CancelTest)
{
    PGHandler handler;
    std::string conn_str(address);
    Connection *conn = PolicyFactory::instance()->createConnection(conn_str, conn_str, &handler);
    conn->reset();
    NonTransaction pg_cancel(&handler);
    pg_cancel.exec(new Query("SELECT 3133 FROM PG_SLEEP(10)", false));
    conn->runTransaction(&pg_cancel);
    while(conn->getStatus() != CONNECTION_OK) {
        if(handler.check() < 1) return;
    }
    ASSERT_EQ(pg_cancel.cancel(), true);
    ASSERT_EQ(pg_cancel.get_status(), Transaction::CANCELING);
    while(pg_cancel.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    ASSERT_EQ(handler.cur_state, PGHandler::FINISH);

    conn->close();
    delete conn;
}

TEST_F(PostgresqlTest, QueryParamTest)
{
    PGHandler handler;
    std::string conn_str(address);
    Connection *conn = PolicyFactory::instance()->createConnection(conn_str, conn_str, &handler);
    conn->reset();
    while(conn->getStatus() != CONNECTION_OK) {
        if(handler.check() < 1) return;
    }
    NonTransaction pg_create(&handler);
    pg_create.exec(new Query("CREATE TABLE IF NOT EXISTS test(id int, value float8, data varchar(50), str json);", false));
    conn->runTransaction(&pg_create);
    while(pg_create.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    ASSERT_EQ(handler.cur_state, PGHandler::FINISH);
    handler.cur_state = PGHandler::CONNECTED;

    NonTransaction pg_insert(&handler);
    QueryParams* q_insert = new QueryParams("INSERT INTO test(id, value, data, str) VALUES($1, $2, $3, $4);", false, false);
    pg_insert.exec(q_insert);
    q_insert->addParam(QueryParam((uint32_t)120));
    q_insert->addParam(QueryParam((float)5.25));
    q_insert->addParam(QueryParam("test"));
    AmArg arg_str;
    arg_str["data"] = "test";
    q_insert->addParam(QueryParam(arg_str));
    conn->runTransaction(&pg_insert);
    while(pg_insert.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    conn->runTransaction(&pg_insert);
    while(pg_insert.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }

    ASSERT_EQ(handler.cur_state, PGHandler::FINISH);
    handler.cur_state = PGHandler::CONNECTED;
    
    NonTransaction pg_select(&handler);
    pg_select.exec(new Query("SELECT * FROM test;", true));
    conn->runTransaction(&pg_select);
    while(pg_select.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    ASSERT_EQ(handler.cur_state, PGHandler::FINISH);
    handler.cur_state = PGHandler::CONNECTED;

    NonTransaction pg_drop(&handler);
    pg_drop.exec(new Query("DROP TABLE test;", false));
    conn->runTransaction(&pg_drop);
    while(pg_drop.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    ASSERT_EQ(handler.cur_state, PGHandler::FINISH);

    conn->close();
    delete conn;
}


TEST_F(PostgresqlTest, QueryPreparedTest)
{
    PGHandler handler;
    std::string conn_str(address);
    Connection *conn = PolicyFactory::instance()->createConnection(conn_str, conn_str, &handler);
    conn->reset();
    while(conn->getStatus() != CONNECTION_OK) {
        if(handler.check() < 1) return;
    }
    NonTransaction pg_create(&handler);
    pg_create.exec(new Query("CREATE TABLE IF NOT EXISTS test(id int, value float8, data varchar(50), str json);", false));
    conn->runTransaction(&pg_create);
    while(pg_create.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    ASSERT_EQ(handler.cur_state, PGHandler::FINISH);
    handler.cur_state = PGHandler::CONNECTED;

    vector<Oid> oids;
    oids.push_back(INT8OID);
    oids.push_back(FLOAT4OID);
    oids.push_back(VARCHAROID);
    oids.push_back(JSONOID);
    PreparedTransaction prt("test_insert",
                            "INSERT INTO test(id, value, data, str) VALUES($1, $2, $3, $4);",
                            oids, &handler);
    conn->runTransaction(&prt);
    while(prt.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    ASSERT_EQ(handler.cur_state, PGHandler::FINISH);
    handler.cur_state = PGHandler::CONNECTED;
    NonTransaction pg_insert(&handler);
    QueryParams* q_insert = new QueryParams("test_insert", false, true);
    pg_insert.exec(q_insert);
    AmArg arg_str;
    arg_str["data"] = "test";
    q_insert->addParam(QueryParam((uint32_t)120)).
              addParam(QueryParam((float)5.25)).
              addParam(QueryParam("test")).
              addParam(QueryParam(arg_str));
    conn->runTransaction(&pg_insert);
    while(pg_insert.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    ASSERT_EQ(handler.cur_state, PGHandler::FINISH);
    handler.cur_state = PGHandler::CONNECTED;
    NonTransaction pg_select(&handler);
    pg_select.exec(new Query("SELECT * FROM test;", false));
    conn->runTransaction(&pg_select);
    while(pg_select.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    ASSERT_EQ(handler.cur_state, PGHandler::FINISH);
    handler.cur_state = PGHandler::CONNECTED;

    NonTransaction pg_drop(&handler);
    pg_drop.exec(new Query("DROP TABLE test;", false));
    conn->runTransaction(&pg_drop);
    while(pg_drop.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    ASSERT_EQ(handler.cur_state, PGHandler::FINISH);

    conn->close();
    delete conn;
}

TEST_F(PostgresqlTest, DbTransactionTest)
{
    PGHandler handler;
    std::string conn_str(address);
    Connection *conn = PolicyFactory::instance()->createConnection(conn_str, conn_str, &handler);
    conn->reset();
    while(conn->getStatus() != CONNECTION_OK) {
        if(handler.check() < 1) return;
    }
    DbTransaction<PGTransactionData::read_committed, PGTransactionData::write_policy::read_write> pg_create(&handler);
    pg_create.exec(new Query("CREATE TABLE IF NOT EXISTS test(id int, value float8, data varchar(50), str json);", false));
    conn->runTransaction(&pg_create);
    while(pg_create.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    ASSERT_EQ(handler.cur_state, PGHandler::FINISH);
    handler.cur_state = PGHandler::CONNECTED;

    NonTransaction pg_drop(&handler);
    pg_drop.exec(new Query("DROP TABLE test;", false));
    conn->runTransaction(&pg_drop);
    while(pg_drop.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    ASSERT_EQ(handler.cur_state, PGHandler::FINISH);

    conn->close();
    delete conn;
}

TEST_F(PostgresqlTest, DbTransactionErrorTest)
{
    PGHandler handler;
    std::string conn_str(address);
    Connection *conn = PolicyFactory::instance()->createConnection(conn_str, conn_str, &handler);
    conn->reset();
    while(conn->getStatus() != CONNECTION_OK) {
        if(handler.check() < 1) return;
    }
    DbTransaction<PGTransactionData::read_committed, PGTransactionData::write_policy::read_write> pg_create(&handler);
    QueryChain* query = new QueryChain(new Query("CREATE TABLE IF NOT EXISTS test(id int, value float8, data varchar(50), str json);", false));
    string query_str("INSERT INTO test(id) VALUES(\"xa-xa\")");
    server->addError(query_str, false);
    query->addQuery(new Query(query_str, false));
    pg_create.exec(query);
    conn->runTransaction(&pg_create);
    while(pg_create.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    ASSERT_EQ(handler.cur_state, PGHandler::FINISH);
    handler.cur_state = PGHandler::CONNECTED;

    conn->close();
    delete conn;
}

TEST_F(PostgresqlTest, ChainQueryTest)
{
    PGHandler handler;
    std::string conn_str(address);
    Connection *conn = PolicyFactory::instance()->createConnection(conn_str, conn_str, &handler);
    conn->reset();
    while(conn->getStatus() != CONNECTION_OK) {
        if(handler.check() < 1) return;
    }

    QueryParams* q_insert = new QueryParams("INSERT INTO test(id, value, data, str) VALUES($1, $2, $3, $4);", false, false);
    q_insert->addParam(QueryParam((uint32_t)120));
    q_insert->addParam(QueryParam((float)5.25));
    q_insert->addParam(QueryParam("test"));
    AmArg arg_str;
    arg_str["data"] = "test";
    q_insert->addParam(QueryParam(arg_str));

    QueryChain* q_chain = new QueryChain(new QueryParams("CREATE TABLE IF NOT EXISTS test(id int, value float8, data varchar(50), str json);", false, false));
    q_chain->addQuery(q_insert);
    q_chain->addQuery(new QueryParams("SELECT * FROM pg_catalog.pg_tables", true, false));
    q_chain->addQuery(new QueryParams("SELECT * FROM test;", true, false));
    q_chain->addQuery(new QueryParams("DROP TABLE test;", false, false));

    NonTransaction pg_create(&handler);
    pg_create.exec(q_chain);
    conn->runTransaction(&pg_create);
    while(pg_create.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    ASSERT_EQ(handler.cur_state, PGHandler::FINISH);
    handler.cur_state = PGHandler::CONNECTED;
    INFO("last success query %s", pg_create.get_query()->get_query().c_str());

    conn->close();
    delete conn;
}

TEST_F(PostgresqlTest, DbTransactionMergeTest)
{
    PGHandler handler;
    Transaction* trans = createDbTransaction(&handler, PGTransactionData::read_committed, PGTransactionData::write_policy::read_only);
    Transaction* trans1 = createDbTransaction(&handler, PGTransactionData::read_committed, PGTransactionData::write_policy::read_only);
    ASSERT_FALSE(trans->merge(trans1));
    trans->exec(new Query("SELECT pg_backend_pid()", false));
    ASSERT_FALSE(trans->merge(trans1));
    trans1->exec(new Query("SELECT pg_backend_pid()", false));
    ASSERT_TRUE(trans->merge(trans1));
    ASSERT_EQ((int)trans->get_size(), 2);
    Transaction* trans2 = createDbTransaction(&handler, PGTransactionData::read_committed, PGTransactionData::write_policy::read_write);
    trans2->exec(new Query("SELECT pg_backend_pid()", false));
    ASSERT_FALSE(trans2->merge(trans));
    Transaction* trans3 = createDbTransaction(&handler, PGTransactionData::read_committed, PGTransactionData::write_policy::read_only);
    trans3->exec(new Query("SELECT pg_backend_pid()", false));
    ASSERT_EQ((int)trans3->get_size(), 1);
    ASSERT_TRUE(trans3->merge(trans));
    ASSERT_EQ((int)trans3->get_size(), 3);

    delete trans;
    delete trans1;
    delete trans2;
    delete trans3;
}

TEST_F(PostgresqlTest, DbPipelineTest)
{
    PGHandler handler;
    std::string conn_str(address);
    Connection *conn = PolicyFactory::instance()->createConnection(conn_str, conn_str, &handler);
    conn->reset();
    while(conn->getStatus() != CONNECTION_OK) {
        if(handler.check() < 1) return;
    }

    conn->startPipeline();
    NonTransaction pg(&handler);
    QueryChain* query = new QueryChain(new QueryParams("SELECT repeat('0', 10), pg_sleep(1)", false, false));
    query->addQuery(new QueryParams("SELECT repeat('1', 10), pg_sleep(1)", false, false));
    query->addQuery(new QueryParams("SELECT repeat('1', 10), pg_sleep(1)", false, false));
    query->addQuery(new QueryParams("SELECT repeat('2', 10), pg_sleep(1)", false, false));
    query->addQuery(new QueryParams("SELECT repeat('3', 10), pg_sleep(1)", false, false));
    query->addQuery(new QueryParams("SELECT repeat('4', 10), pg_sleep(1)", false, false));
    pg.exec(query);

    conn->runTransaction(&pg);

    while(pg.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    INFO("last success query %s", pg.get_query()->get_query().c_str());
}

TEST_F(PostgresqlTest, DbPipelineErrorTest)
{
    PGHandler handler;
    std::string conn_str(address);
    Connection *conn = PolicyFactory::instance()->createConnection(conn_str, conn_str, &handler);
    conn->reset();
    while(conn->getStatus() != CONNECTION_OK) {
        if(handler.check() < 1) return;
    }

    conn->startPipeline();
    NonTransaction pg1(&handler);
    QueryChain* query = new QueryChain(new QueryParams("SELECT repeat('0', 10), pg_sleep(1)", false, false));
    query->addQuery(new QueryParams("SELECT TTT", false, false));
    query->addQuery(new QueryParams("SELECT repeat('0', 10), pg_sleep(1)", false, false));
    query->addQuery(new QueryParams("SELECT repeat('0', 10), pg_sleep(1)", false, false));
    pg1.exec(query);
    server->addError("SELECT TTT", false);

    conn->runTransaction(&pg1);

    while(pg1.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }

    NonTransaction pg2(&handler);
    pg2.exec(new QueryParams("SELECT repeat('0', 10), pg_sleep(1)", false, false));

    conn->runTransaction(&pg2);

    while(pg2.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
}

TEST_F(PostgresqlTest, DbPipelineSyncErrorTest)
{
    PGHandler handler;
    std::string conn_str(address);
    Connection *conn = PolicyFactory::instance()->createConnection(conn_str, conn_str, &handler);
    conn->reset();
    while(conn->getStatus() != CONNECTION_OK) {
        if(handler.check() < 1) return;
    }

    conn->startPipeline();
    NonTransaction pg1(&handler);
    QueryChain* query = new QueryChain(new QueryParams("SELECT repeat('0', 10), pg_sleep(1)", false, false));
    query->addQuery(new QueryParams("SELECT repeat('0', 10), pg_sleep(1)", false, false));
    query->addQuery(new QueryParams("SELECT repeat('1', 10), pg_sleep(1)", false, false));
    pg1.exec(query);
    server->setSyncError();

    conn->runTransaction(&pg1);

    while(pg1.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
}

TEST_F(PostgresqlTest, DbPipelineAbortedTest)
{
    PGHandler handler;
    std::string conn_str(address);
    Connection *conn = PolicyFactory::instance()->createConnection(conn_str, conn_str, &handler);
    conn->reset();
    while(conn->getStatus() != CONNECTION_OK) {
        if(handler.check() < 1) return;
    }

    conn->startPipeline();

    NonTransaction pg3(&handler);
    QueryChain* query = new QueryChain(new QueryParams("CREATE TABLE IF NOT EXISTS test(id int, value float8, data varchar(50), str json);", false, false));
    query->addQuery(new QueryParams("SELECT TTT", false, false));
    pg3.exec(query);
    server->addError("SELECT TTT", false);

    conn->runTransaction(&pg3);

    while(pg3.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }

    NonTransaction pg4(&handler);
    query = new QueryChain(new QueryParams("SELECT * FROM test;", false, false));
    query->addQuery(new QueryParams("DROP TABLE test;", false, false));
    pg4.exec(query);
    server->addError("SELECT * FROM test;", false);
    conn->runTransaction(&pg4);

    while(pg4.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }

    NonTransaction pg2(&handler);
    pg2.exec(new QueryParams("SELECT repeat('0', 10), pg_sleep(1)", false, false));

    conn->runTransaction(&pg2);

    while(pg2.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
}

TEST_F(PostgresqlTest, DbPipelineTransactionTest)
{
    PGHandler handler;
    std::string conn_str(address);
    Connection *conn = PolicyFactory::instance()->createConnection(conn_str, conn_str, &handler);
    conn->reset();
    while(conn->getStatus() != CONNECTION_OK) {
        if(handler.check() < 1) return;
    }

    conn->startPipeline();
    Transaction* pg2 = createDbTransaction(&handler, PGTransactionData::read_committed, PGTransactionData::write_policy::read_write);
    QueryChain* query = new QueryChain(new QueryParams("SELECT repeat('0', 10), pg_sleep(1)", false, false));
    query->addQuery(new QueryParams("SELECT repeat('1', 10), pg_sleep(1)", false, false));
    query->addQuery(new QueryParams("SELECT repeat('2', 10), pg_sleep(1)", false, false));
    query->addQuery(new QueryParams("SELECT repeat('3', 10), pg_sleep(1)", false, false));
    query->addQuery(new QueryParams("SELECT repeat('4', 10), pg_sleep(1)", false, false));
    pg2->exec(query);

    conn->runTransaction(pg2);

    while(pg2->get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    delete pg2;
}

TEST_F(PostgresqlTest, DISABLED_DbPipelineStressTest)
{
    PGHandler handler;
    std::string conn_str(address);
    Connection *conn = PolicyFactory::instance()->createConnection(conn_str, conn_str, &handler);
    conn->reset();
    while(conn->getStatus() != CONNECTION_OK) {
        if(handler.check() < 1) return;
    }

    conn->startPipeline();
    Transaction* pg2 = createDbTransaction(&handler, PGTransactionData::read_committed, PGTransactionData::write_policy::read_write);
    string q = "SELECT * from json_each_text('{";
    for(int i = 0; i < 10000000; i++) {
        if(i) q += ", ";
        char index[100] = {0};
        sprintf(index, "\"i_%d\":\"%d\"", i, i);
        q += index;
    }
    q += "}')";
    INFO("size of query %d", q.size());
    QueryParams* query = new QueryParams(q, false, false);
    pg2->exec(query);

    conn->runTransaction(pg2);

    while(pg2->get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    delete pg2;
}

TEST_F(PostgresqlTest, DbPipelineTransErrorTest)
{
    PGHandler handler;
    std::string conn_str(address);
    Connection *conn = PolicyFactory::instance()->createConnection(conn_str, conn_str, &handler);
    conn->reset();
    while(conn->getStatus() != CONNECTION_OK) {
        if(handler.check() < 1) return;
    }

    conn->startPipeline();
    Transaction* pg1 = createDbTransaction(&handler, PGTransactionData::read_committed, PGTransactionData::write_policy::read_write);
    QueryChain* query = new QueryChain(new QueryParams("CREATE TABLE IF NOT EXISTS test(id int, value float8, data varchar(50), str json);", false, false));
    query->addQuery(new QueryParams("SELECT TTT", false, false));
    pg1->exec(query);
    server->addError("SELECT TTT", false);

    conn->runTransaction(pg1);

    while(pg1->get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    delete pg1;

    pg1 = createDbTransaction(&handler, PGTransactionData::read_committed, PGTransactionData::write_policy::read_write);
    query = new QueryChain(new QueryParams("CREATE TABLE IF NOT EXISTS test(id int, value float8, data varchar(50), str json);", false, false));
    pg1->exec(query);

    conn->runTransaction(pg1);

    while(pg1->get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
    delete pg1;

    NonTransaction drop(&handler);
    drop.exec(new QueryParams("DROP TABLE test;", false, false));
    conn->runTransaction(&drop);
    while(drop.get_status() != Transaction::FINISH) {
        if(handler.check() < 1) return;
    }
}

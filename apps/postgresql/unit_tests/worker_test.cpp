#include "PGHandler.h"
#include "WorkerHandler.h"
#include "../ConnectionPool.h"
#include "../PostgreSQL.h"
#include "../pqtypes-int.h"

#define CREATE_TABLE "CREATE TABLE IF NOT EXISTS test(id int, value float8, data varchar(50), str json);"
#define INSERT_INTO_PARAM "INSERT INTO test(id, value, data, str) VALUES($1, $2, $3, $4);"
#define INSERT_INTO "INSERT INTO test(id, value, data, str) VALUES(1, 5.13, \'test\', \'{}\');"
#define DROP_TABLE "DROP TABLE test;"
#define BACKEND "SELECT pg_backend_pid();"

PGPool GetPoolByAddress(const string& address)
{
    vector<string> params;
    size_t pos = string::npos, first = 0;
    do {
        pos = address.find(" ", first);
        string data;
        if(pos != string::npos)
            data.append(address.begin() + first, address.begin() + pos);
        else
            data.append(address.begin() + first, address.end());
        if(!data.empty())
            params.push_back(data);
        first = pos + 1;
    } while(pos != string::npos);

    string host, user, pass, db;
    int port;

    for(auto& param : params) {
        string p, v;
        pos = param.find("=");
        if(pos == string::npos)
            continue;
        p.append(param.begin(), param.begin() + pos);
        v.append(param.begin() + pos + 1, param.end());
        if(p == "host")
            host = v;
        else if(p == "port") {
            if(!str2int(v, port))
                ERROR("incorrect port value `%s` in address", v.c_str());
        } else if(p == "user")
            user = v;
        else if(p == "dbname")
            db = v;
        else if(p == "password")
            pass = v;
    }

    return PGPool(host, port, db, user, pass);
}

TEST_F(PostgresqlTest, WorkerConnectionTest)
{
    PGPool pool = GetPoolByAddress(address);
    pool.pool_size = 1;
    PostgreSQL::instance()->postEvent(new PGWorkerPoolCreate("test", PGWorkerPoolCreate::Master, pool));
    sleep(1);
    AmArg arg;
    PostgreSQL::instance()->showStats(arg, arg);
    INFO("%s", AmArg::print(arg).c_str());
    ASSERT_TRUE(arg.hasMember("workers"));
    AmArg arg1 = arg["workers"];
    ASSERT_TRUE(arg1.hasMember("test"));
    arg = arg1["test"]["stats"];
    ASSERT_TRUE(arg.hasMember("master"));
    ASSERT_TRUE(isArgArray(arg["master"]));
    ASSERT_FALSE(isArgArray(arg["slave"]));
    ASSERT_EQ((int)arg["master"].size(), 1);
    bool exit = false;
    while(exit) {
        sleep(1);
        arg.clear();
        PostgreSQL::instance()->showStats(arg, arg);
        INFO("%s", AmArg::print(arg).c_str());
        arg1 = arg["workers"]["test"]["stats"];
        exit = true;
        for(size_t i = 0; i < arg1["master"].size(); i++) {
            if(arg1["master"][i]["status"].asInt() != CONNECTION_OK)
                exit = false;
        }
    }
}


TEST_F(PostgresqlTest, WorkerDestroyTest)
{
    PGPool pool = GetPoolByAddress(address);
    pool.pool_size = 1;
    PostgreSQL::instance()->postEvent(new PGWorkerPoolCreate("test", PGWorkerPoolCreate::Master, pool));
    sleep(1);
    AmArg arg;
    PostgreSQL::instance()->showStats(arg, arg);
    ASSERT_TRUE(arg["workers"].hasMember("test"));

    PostgreSQL::instance()->postEvent(new PGWorkerDestroy("test"));
    sleep(1);
    arg.clear();
    PostgreSQL::instance()->showStats(arg, arg);
    ASSERT_FALSE(arg["workers"].hasMember("test"));
}



TEST_F(PostgresqlTest, WorkerTransactionTest)
{
    vector<PGEvent::Type> types = {PGEvent::Result, PGEvent::Result};
    WorkerHandler::instance().set_expected_events(types);

    string query(BACKEND);
    AmArg resp;
    resp.push("pg_backend_pid", 4565);
    server.addResponse(query, resp);

    PGQueryData qdata(WORKER_POOL_NAME, query, false, WORKER_HANDLER_QUEUE, "token transaction test");
    PostgreSQL::instance()->postEvent(new PGExecute(qdata, PGTransactionData()));
    PostgreSQL::instance()->postEvent(new PGExecute(qdata, PGTransactionData(PGTransactionData::read_committed, PGTransactionData::write_policy::read_write)));
    WorkerHandler::instance().run();

    AmArg arg;
    PostgreSQL::instance()->showStats(arg, arg);
    AmArg arg1 = arg["workers"][WORKER_POOL_NAME]["stats"];
    for(size_t i = 0; i < arg1["master"].size(); i++) {
        ASSERT_FALSE(arg1["master"][i]["busy"].asBool());
    }
}

TEST_F(PostgresqlTest, WorkerTransactionParamTest)
{
    vector<PGEvent::Type> types = {PGEvent::Result, PGEvent::Result};
    WorkerHandler::instance().set_expected_events(types);

    PGWorkerConfig* wc = new PGWorkerConfig(WORKER_POOL_NAME, false, true, false, 1, 1, 1, DEFAULT_BATCH_SIZE, 1);
    PostgreSQL::instance()->postEvent(wc);

    string query;
    query = INSERT_INTO_PARAM;
    server.addResponse(query, AmArg());
    server.addError(query, true);
    PGQueryData qdata1(WORKER_POOL_NAME, query, false, WORKER_HANDLER_QUEUE);
    PGParamExecute* ev = new PGParamExecute(qdata1, PGTransactionData(), false);
    AmArg arg_str;
    arg_str["data"] = "test";
    ev->addParam(120).addParam(5.25).addParam("test").addParam(arg_str);
    PostgreSQL::instance()->postEvent(ev);

    query = CREATE_TABLE;
    server.addResponse(query, AmArg());
    PGQueryData qdata(WORKER_POOL_NAME, query, false, WORKER_HANDLER_QUEUE);
    PostgreSQL::instance()->postEvent(new PGExecute(qdata, PGTransactionData()));

    WorkerHandler::instance().run();
    {
        AmArg arg;
        PostgreSQL::instance()->showStats(arg, arg);
        AmArg arg1 = arg["workers"][WORKER_POOL_NAME]["stats"];
        for(size_t i = 0; i < arg1["master"].size(); i++) {
            ASSERT_FALSE(arg1["master"][i]["busy"].asBool());
        }
    }
    types = {PGEvent::Result};
    WorkerHandler::instance().set_expected_events(types);

    query = "SELECT * FROM test;";
    AmArg resp;
    resp.push("id", 120);
    resp.push("value", 5.25);
    resp.push("data", "test");
    resp.push("str", AmArg());
    resp["str"].push("data", "test");
    server.addResponse(query, resp);
    PGQueryData qdata2(WORKER_POOL_NAME, query, false, WORKER_HANDLER_QUEUE);
    PostgreSQL::instance()->postEvent(new PGExecute(qdata2, PGTransactionData()));
    WorkerHandler::instance().run();
    {
        AmArg arg;
        PostgreSQL::instance()->showStats(arg, arg);
        AmArg arg1 = arg["workers"][WORKER_POOL_NAME]["stats"];
        for(size_t i = 0; i < arg1["master"].size(); i++) {
            ASSERT_FALSE(arg1["master"][i]["busy"].asBool());
        }
    }
    WorkerHandler::instance().set_expected_events(types);

    query = DROP_TABLE;
    server.addResponse(query, AmArg());
    PGQueryData qdata3(WORKER_POOL_NAME, query, false, WORKER_HANDLER_QUEUE);
    PostgreSQL::instance()->postEvent(new PGExecute(qdata3, PGTransactionData()));

    WorkerHandler::instance().run();
    {
        AmArg arg;
        PostgreSQL::instance()->showStats(arg, arg);
        AmArg arg1 = arg["workers"][WORKER_POOL_NAME]["stats"];
        for(size_t i = 0; i < arg1["master"].size(); i++) {
            ASSERT_FALSE(arg1["master"][i]["busy"].asBool());
        }
    }
}

TEST_F(PostgresqlTest, WorkerPrepareTest)
{
    vector<PGEvent::Type> types = {PGEvent::Result};
    WorkerHandler::instance().set_expected_events(types);

    string query;
    query = CREATE_TABLE;
    server.addResponse(query, AmArg());
    PGQueryData qdata(WORKER_POOL_NAME, query, false, WORKER_HANDLER_QUEUE);
    PostgreSQL::instance()->postEvent(new PGExecute(qdata, PGTransactionData()));

    WorkerHandler::instance().run();
    {
        AmArg arg;
        PostgreSQL::instance()->showStats(arg, arg);
        AmArg arg1 = arg["workers"][WORKER_POOL_NAME]["stats"];
        for(size_t i = 0; i < arg1["master"].size(); i++) {
            ASSERT_FALSE(arg1["master"][i]["busy"].asBool());
        }
    }
    WorkerHandler::instance().set_expected_events(types);

    query = INSERT_INTO_PARAM;
    PGPrepare* pr = new PGPrepare(WORKER_POOL_NAME, "insert", query);
    pr->add_param_oid(INT8OID).add_param_oid(FLOAT4OID).add_param_oid(VARCHAROID).add_param_oid(JSONOID);
    PostgreSQL::instance()->postEvent(pr);
    bool wait = true;
    while(wait)
    {
        AmArg arg;
        PostgreSQL::instance()->showStats(arg, arg);
        AmArg arg1 = arg["workers"][WORKER_POOL_NAME]["stats"];
        bool busy = false;
        for(size_t i = 0; i < arg1["master"].size(); i++) {
            if(arg1["master"][i]["busy"].asBool()) {
                busy = true;
                break;
            }
            wait = busy;
        }
        sleep(1);
    }
    WorkerHandler::instance().set_expected_events(types);

    query = DROP_TABLE;
    server.addResponse(query, AmArg());
    PGQueryData qdata3(WORKER_POOL_NAME, query, false, WORKER_HANDLER_QUEUE);
    PostgreSQL::instance()->postEvent(new PGExecute(qdata3, PGTransactionData()));

    WorkerHandler::instance().run();
    {
        AmArg arg;
        PostgreSQL::instance()->showStats(arg, arg);
        AmArg arg1 = arg["workers"][WORKER_POOL_NAME]["stats"];
        for(size_t i = 0; i < arg1["master"].size(); i++) {
            ASSERT_FALSE(arg1["master"][i]["busy"].asBool());
        }
    }
}

TEST_F(PostgresqlTest, WorkerPrepareExecTest)
{
    vector<PGEvent::Type> types = {PGEvent::Result};
    WorkerHandler::instance().set_expected_events(types);

    string query;
    query = CREATE_TABLE;
    server.addResponse(query, AmArg());
    PGQueryData qdata(WORKER_POOL_NAME, query, false, WORKER_HANDLER_QUEUE);
    PostgreSQL::instance()->postEvent(new PGExecute(qdata, PGTransactionData()));

    WorkerHandler::instance().run();
    {
        AmArg arg;
        PostgreSQL::instance()->showStats(arg, arg);
        AmArg arg1 = arg["workers"][WORKER_POOL_NAME]["stats"];
        for(size_t i = 0; i < arg1["master"].size(); i++) {
            ASSERT_FALSE(arg1["master"][i]["busy"].asBool());
        }
    }
    WorkerHandler::instance().set_expected_events(types);

    query = INSERT_INTO_PARAM;
    server.addResponse(query, AmArg());
    PGQueryData qdata1(WORKER_POOL_NAME, query, false, WORKER_HANDLER_QUEUE);
    PGPrepareExec* pr = new PGPrepareExec(qdata1, "add");
    AmArg arg_str;
    arg_str["data"] = "test";
    pr->addParam(120).addParam(5.25).addParam("test").addParam(arg_str);
    PostgreSQL::instance()->postEvent(pr);

    WorkerHandler::instance().run();
    {
        AmArg arg;
        PostgreSQL::instance()->showStats(arg, arg);
        AmArg arg1 = arg["workers"][WORKER_POOL_NAME]["stats"];
        for(size_t i = 0; i < arg1["master"].size(); i++) {
            ASSERT_FALSE(arg1["master"][i]["busy"].asBool());
        }
    }
    WorkerHandler::instance().set_expected_events(types);

    query = DROP_TABLE;
    server.addResponse(query, AmArg());
    PGQueryData qdata3(WORKER_POOL_NAME, query, false, WORKER_HANDLER_QUEUE);
    PostgreSQL::instance()->postEvent(new PGExecute(qdata3, PGTransactionData()));

    WorkerHandler::instance().run();
    {
        AmArg arg;
        PostgreSQL::instance()->showStats(arg, arg);
        AmArg arg1 = arg["workers"][WORKER_POOL_NAME]["stats"];
        for(size_t i = 0; i < arg1["master"].size(); i++) {
            ASSERT_FALSE(arg1["master"][i]["busy"].asBool());
        }
    }
}

TEST_F(PostgresqlTest, WorkerConfigTest)
{
    PGPool pool = GetPoolByAddress(address);
    pool.pool_size = 1;
    PostgreSQL::instance()->postEvent(new PGWorkerPoolCreate("test", PGWorkerPoolCreate::Master, pool));
    PGWorkerConfig* wc = new PGWorkerConfig("test", false, false, false, 2);
    wc->addPrepared("backend", BACKEND);
    wc->addPrepared("sleep", "SELECT pg_sleep($1)").add_param_oid(INT4OID);
    PostgreSQL::instance()->postEvent(wc);

    AmArg resp;
    resp.push("pg_backend_pid", 4565);
    server.addResponse("backend", resp);
    server.addResponse("sleep", AmArg());
    PGQueryData qdata("test", "backend", false, WORKER_HANDLER_QUEUE);
    PGParamExecute* ev = new PGParamExecute(qdata, PGTransactionData(), true);
    PostgreSQL::instance()->postEvent(ev);
    PGQueryData qdata1("test", "sleep", false, WORKER_HANDLER_QUEUE);
    ev = new PGParamExecute(qdata1, PGTransactionData(), true);
    ev->addParam(1);
    PostgreSQL::instance()->postEvent(ev);

    vector<PGEvent::Type> types = {PGEvent::Result, PGEvent::Result};
    WorkerHandler::instance().set_expected_events(types);
    WorkerHandler::instance().run();
    {
        AmArg arg;
        PostgreSQL::instance()->showStats(arg, arg);
        AmArg arg1 = arg["workers"][WORKER_POOL_NAME]["stats"];
        for(size_t i = 0; i < arg1["master"].size(); i++) {
            ASSERT_FALSE(arg1["master"][i]["busy"].asBool());
        }
    }
}

TEST_F(PostgresqlTest, WorkerQueueTest)
{
    PGHandler handler;
    Worker worker("test", handler.epoll_fd);
    handler.workers.push_back(&worker);
    PGPool pool = GetPoolByAddress(address);
    pool.pool_size = 1;
    worker.createPool(PGWorkerPoolCreate::Master, pool);
    PGWorkerConfig config("test", false, false, false);
    config.batch_size = 4;
    config.batch_timeout = 2;
    worker.configure(config);

    AmArg resp;
    resp.push("pg_backend_pid", 4565);
    server.addResponse(BACKEND, resp);
    IPGTransaction* trans = new NonTransaction(&worker);
    trans->exec(new Query(BACKEND, false));
    worker.runTransaction(trans, "", "");
    trans = createDbTransaction(&worker, PGTransactionData::read_committed, PGTransactionData::write_policy::read_only);
    trans->exec(new Query(BACKEND, false));
    worker.runTransaction(trans, "", "");
    trans = createDbTransaction(&worker, PGTransactionData::read_committed, PGTransactionData::write_policy::read_only);
    trans->exec(new Query(BACKEND, false));
    worker.runTransaction(trans, "", "");
    while(true){
        if(handler.check() < 1) return;
        AmArg arg;
        worker.getStats(arg);
        if(arg["stats"]["finished"].asInt() == 3) break;
    }
}

TEST_F(PostgresqlTest, WorkerQueueErrorTest)
{
    PGHandler handler;
    Worker worker("test", handler.epoll_fd);
    handler.workers.push_back(&worker);
    PGPool pool = GetPoolByAddress(address);
    pool.pool_size = 2;
    worker.createPool(PGWorkerPoolCreate::Master, pool);
    PGWorkerConfig config("test", false, true, false, 3, 1);
    config.batch_size = 4;
    worker.configure(config);

    server.addResponse(CREATE_TABLE, AmArg());
    server.addResponse(INSERT_INTO, AmArg());
    server.addError("ASSERT 0", false);
    IPGTransaction* trans = createDbTransaction(&worker, PGTransactionData::read_committed, PGTransactionData::write_policy::read_write);
    trans->exec(new Query(CREATE_TABLE, false));
    worker.runTransaction(trans, "", "");
    trans = createDbTransaction(&worker, PGTransactionData::read_committed, PGTransactionData::write_policy::read_write);
    trans->exec(new Query("ASSERT 0", false));
    worker.runTransaction(trans, "", "");
    trans = createDbTransaction(&worker, PGTransactionData::read_committed, PGTransactionData::write_policy::read_write);
    trans->exec(new Query(INSERT_INTO, false));
    worker.runTransaction(trans, "", "");
    while(true){
        if(handler.check() < 1) return;
        AmArg stats;
        worker.getStats(stats);
        auto &arg = stats["stats"];
        if(arg["finished"].asInt() == 2 &&
           arg["retransmit"].asInt() == 1)
        {
            break;
        }
        usleep(500);
    }

    trans = new NonTransaction(&worker);
    trans->exec(new Query(DROP_TABLE, false));
    worker.runTransaction(trans, "", "");
    while(true){
        if(handler.check() < 1) return;
        AmArg stats;
        worker.getStats(stats);
        auto &arg = stats["stats"];
        if(arg["finished"].asInt() == 3 &&
           arg["retransmit"].asInt() == 1)
        {
            break;
        }
        usleep(500);
    }
}

TEST_F(PostgresqlTest, WorkerTransactionOnResetConnectionTest)
{
    PGHandler handler;
    Worker worker("test", handler.epoll_fd);
    handler.workers.push_back(&worker);
    PGPool pool = GetPoolByAddress(address);
    pool.pool_size = 2;
    worker.createPool(PGWorkerPoolCreate::Master, pool);
    PGWorkerConfig config("test", false, true, false, 15, 1);
    config.batch_size = 2;
    worker.configure(config);
    IPGTransaction* trans = new NonTransaction(&worker);
    trans->exec(new Query("SELECT pg_sleep(1)", false));
    worker.runTransaction(trans, "", "");
    trans = createDbTransaction(&worker, PGTransactionData::read_committed, PGTransactionData::write_policy::read_write);
    trans->exec(new Query(CREATE_TABLE, false));
    worker.runTransaction(trans, "", "");
    trans = createDbTransaction(&worker, PGTransactionData::read_committed, PGTransactionData::write_policy::read_write);
    trans->exec(new Query("SELECT pg_sleep(3)", false));
    worker.runTransaction(trans, "", "");
    while(true){
        if(handler.check() < 1) return;
        AmArg arg;
        worker.getStats(arg);
        if(arg["stats"]["finished"].asInt() == 1) break;
        usleep(500);
    }
    worker.resetPools();

    while(true){
        if(handler.check() < 1) return;
        AmArg arg;
        worker.getStats(arg);
        if(arg["stats"]["finished"].asInt() == 3) break;
        usleep(500);
    }

    trans = new NonTransaction(&worker);
    trans->exec(new Query(DROP_TABLE, false));
    worker.runTransaction(trans, "", "");
    while(true){
        if(handler.check() < 1) return;
        AmArg arg;
        worker.getStats(arg);
        if(arg["stats"]["finished"].asInt() == 4) break;
        usleep(500);
    }
}

TEST_F(PostgresqlTest, WorkerSearchPathTest)
{
    PGHandler handler;
    Worker worker("test", handler.epoll_fd);
    handler.workers.push_back(&worker);
    PGPool pool = GetPoolByAddress(address);
    pool.pool_size = 2;
    worker.createPool(PGWorkerPoolCreate::Master, pool);

    while(true) {
        if(handler.check() < 1) return;
        AmArg arg;
        worker.getStats(arg);
        if(arg["stats"]["master"][0]["status"].asInt() == CONNECTION_OK ||
           arg["stats"]["master"][1]["status"].asInt() == CONNECTION_OK) break;
    }

    PGSetSearchPath spath("test");
    spath.addSearchPath("public");
    worker.setSearchPath(spath.search_pathes);

    while(true) {
        if(handler.check() < 1) return;
        AmArg stats;
        worker.getStats(stats);
        auto &arg = stats["stats"];
        if(!arg["master"][0]["busy"].asBool() && 
           !arg["master"][1]["busy"].asBool() &&
           arg["master"][0]["status"].asInt() == CONNECTION_OK &&
           arg["master"][1]["status"].asInt() == CONNECTION_OK) break;
    }
}

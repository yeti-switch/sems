#pragma once

#include "AmEvent.h"

#include <string>
using std::string;

#define POSTGRESQL_QUEUE       "postgresql"
#define PG_DEFAULT_POOL_SIZE      6
#define PG_DEFAULT_BATCH_SIZE     0
#define PG_DEFAULT_MAX_Q_LEN      10000
#define PG_DEFAULT_BATCH_TIMEOUT 1      //in sec
#define PG_DEFAULT_RET_INTERVAL   10     //in sec
#define PG_DEFAULT_REC_INTERVAL   1      //in sec
#define PG_DEFAULT_WAIT_TIME      5      //in sec

class PGEvent : public AmEvent
{
public:
    enum Type {
        WorkerPoolCreate = 0,
        WorkerConfig,
        WorkerDestroy,
        SetSearchPath,
        SimpleExecute,
        ParamExecute,
        Prepare,
        PrepareExec,
        Result,
        ResultError,
        Timeout
    };

    PGEvent(int event_id) : AmEvent(event_id){}
};

struct PGPool
{
    //required parameters
    string host;
    uint16_t port;
    string name;
    string user;
    string pass;

    //optional parameters
    uint8_t pool_size;

    PGPool(const string& host_, uint16_t port_,
           const string& name_, const string& user_, const string& pass_)
        : host(host_), port(port_), name(name_), user(user_), pass(pass_)
        , pool_size(PG_DEFAULT_POOL_SIZE){}
    PGPool(const PGPool& pool)
        : host(pool.host), port(pool.port), name(pool.name), user(pool.user), pass(pool.pass)
        , pool_size(pool.pool_size){}
};

class PGWorkerPoolCreate : public PGEvent
{
public:

    enum PoolType
    {
        Master = 0,
        Slave
    };

    string worker_name;
    PoolType type;
    PGPool pool;

    PGWorkerPoolCreate(const string& name_, PoolType type_, const PGPool& pool_) 
        : PGEvent(WorkerPoolCreate)
        , worker_name(name_), type(type_)
        , pool(pool_){}
};

class PGWorkerDestroy : public PGEvent
{
public:
    string worker_name;

    PGWorkerDestroy(string name_) : PGEvent(WorkerDestroy), worker_name(name_) {}
};

class PGPrepareData
{
public:
    string stmt;
    string query;
    vector<unsigned int> oids;
    vector<string> sql_types;

    PGPrepareData(const string& stmt_, const string& query_)
    : stmt(stmt_), query(query_) {}
    PGPrepareData(const PGPrepareData& data)
    : stmt(data.stmt), query(data.query)
    , oids(data.oids)
    , sql_types(data.sql_types)
    {}

    PGPrepareData& add_param_oid(unsigned int oid) {
        oids.push_back(oid);
        return *this;
    }

    PGPrepareData& add_sql_type_param(const string &sql_type) {
        sql_types.emplace_back(sql_type);
        return *this;
    }
};

class PGWorkerConfig : public PGEvent
{
public:
    string worker_name;
    uint32_t batch_size;
    uint32_t batch_timeout;
    uint32_t max_queue_length;
    bool failover_to_slave;
    bool retransmit_enable;
    uint32_t trans_wait_time;
    uint32_t retransmit_interval;
    uint32_t reconnect_interval;
    bool use_pipeline;
    vector<PGPrepareData> prepeared;
    vector<string> search_pathes;

    PGWorkerConfig(
        const string& name,
       bool failover_to_slave,
       bool retransmit_enable,
       bool use_pipeline,
       uint32_t trans_wait_time = PG_DEFAULT_WAIT_TIME,
       uint32_t retransmit_interval = PG_DEFAULT_RET_INTERVAL,
       uint32_t reconnect_interval = PG_DEFAULT_REC_INTERVAL,
       uint32_t batch_size = PG_DEFAULT_BATCH_SIZE,
       uint32_t batch_timeout = PG_DEFAULT_BATCH_TIMEOUT,
       uint32_t max_queue_length = PG_DEFAULT_MAX_Q_LEN)
     : PGEvent(WorkerConfig)
     , worker_name(name)
     , use_pipeline(use_pipeline)
     , failover_to_slave(failover_to_slave)
     , retransmit_enable(retransmit_enable)
     , retransmit_interval(retransmit_interval)
     , reconnect_interval(reconnect_interval)
     , trans_wait_time(trans_wait_time)
     , batch_size(batch_size)
     , batch_timeout(batch_timeout)
     , max_queue_length(max_queue_length)
    {}

    PGPrepareData& addPrepared(const string& stmt_, const string& query_) {
        return prepeared.emplace_back(stmt_, query_);
    }

    void addSearchPath(const string& search_path) {
        search_pathes.push_back(search_path);
    }
};

class PGSetSearchPath : public PGEvent
{
public:
    string worker_name;
    vector<string> search_pathes;

    PGSetSearchPath(string name) : PGEvent(SetSearchPath), worker_name(name) {}

    PGSetSearchPath& addSearchPath(const string& search_path) {
        search_pathes.push_back(search_path);
        return *this;
    }
};

class QueryInfo
{
public:
    string query;
    bool   single;
    vector<AmArg> params;
    QueryInfo(const string& query_, bool single_)
    : query(query_), single(single_){}

    template<typename T>
    QueryInfo& addParam(const T& param){
        params.emplace_back(param);
        return *this;
    }

    template<typename T>
    QueryInfo& addTypedParam(const char *sql_type, const T& param) {
        params.emplace_back();
        AmArg &a = params.back()["pg"];
        a.push(sql_type);
        a.push(param);
        return *this;
    }
};

class PGQueryData
{
public:
    string worker_name;
    string sender_id;
    vector<QueryInfo> info;
    string token;

    PGQueryData(const string& name_, const string& query_,
                bool single, const string& session_id = string(),
                const string& token_ = string())
    : worker_name(name_)
    , sender_id(session_id)
    , token(token_) {
        info.emplace_back(query_, single);
    }
    PGQueryData(const string& name_, const string& session_id = string(),
                const string& token_ = string())
    : worker_name(name_)
    , sender_id(session_id)
    , token(token_){}

    void addQuery(const string& query_, bool single_) {
        info.emplace_back(query_, single_);
    }
};

class PGTransactionData
{
  public:
    bool use_transaction;

    enum isolation_level
    {
    read_committed,
    repeatable_read,
    serializable,
    } il;

    enum class write_policy
    {
    read_only,
    read_write
    } wp;

    PGTransactionData()
      : use_transaction(false),
        il(read_committed),
        wp(write_policy::read_only)
    {}

    PGTransactionData(isolation_level il_, write_policy wp_)
      : use_transaction(true),
        il(il_),
        wp(wp_)
    {}
};

class PGExecute : public PGEvent
{
public:
    PGQueryData qdata;
    PGTransactionData tdata;
    bool initial;

    PGExecute(
        const PGQueryData& qdata_,
        const PGTransactionData& tdata_,
        bool initial = false)
      : PGEvent(SimpleExecute),
        qdata(qdata_),
        tdata(tdata_),
        initial(initial)
    {}
};

class PGParamExecute : public PGEvent
{
public:
    PGQueryData qdata;
    PGTransactionData tdata;
    bool prepared;
    bool initial;

    PGParamExecute(
        const PGQueryData& qdata_,
        const PGTransactionData& tdata_,
        bool prepared_,
        bool initial = false)
     : PGEvent(ParamExecute),
       qdata(qdata_),
       tdata(tdata_),
       prepared(prepared_),
       initial(initial)
    {}

    template<typename T>
    QueryInfo& addParam(const T& param)
    {
        assert(!qdata.info.empty());
        return qdata.info[0].addParam(param);
    }
};

class PGPrepare : public PGEvent
{
public:
    string worker_name;
    PGPrepareData pdata;

    PGPrepare(const string& name_, const string& stmt_, const string& query_)
    : PGEvent(Prepare), worker_name(name_), pdata(stmt_, query_) {}

    PGPrepare& add_param_oid(unsigned int oid) {
        pdata.add_param_oid(oid);
        return *this;
    }
};

class PGPrepareExec : public PGEvent
{
public:
    string worker_name;
    string stmt;
    QueryInfo info;
    string sender_id;
    string token;

    PGPrepareExec(const string& name_, const string& stmt_,
                  const QueryInfo& info_,
                  const string& session_id = string(),
                  const string& token_ = string())
    : PGEvent(PrepareExec), worker_name(name_)
    , stmt(stmt_), info(info_)
    , sender_id(session_id), token(token_){}

    template<typename T>
    QueryInfo& addParam(const T& param)
    {
        return info.addParam(param);
    }
};

class PGResponse : public PGEvent
{
public:
    string token;
    AmArg result;

    PGResponse(const AmArg& res, const string& token_)
    : PGEvent(Result), token(token_), result(res){}
};

class PGResponseError : public PGEvent
{
public:
    string token;
    string error;

    PGResponseError(const string& res, const string& token_)
    : PGEvent(ResultError), token(token_), error(res) {}
};

class PGTimeout : public PGEvent
{
public:
    string token;
    PGTimeout(const string& token_)
    : PGEvent(Timeout), token(token_) {}
};

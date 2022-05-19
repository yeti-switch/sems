#ifndef POSTGRESQL_API_H
#define POSTGRESQL_API_H

#include "AmEvent.h"

#include <string>
using std::string;

#define POSTGRESQL_QUEUE       "postgresql"
#define DEFAULT_POOL_SIZE      6
#define DEFAULT_BATCH_SIZE     0
#define DEFAULT_MAX_Q_LEN      10000
#define DEFAULT_BATCH_TIMEOUT 1      //in sec
#define DEFAULT_RET_INTERVAL   10     //in sec
#define DEFAULT_REC_INTERVAL   1      //in sec
#define DEFAULT_WAIT_TIME      5      //in sec

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
        , pool_size(DEFAULT_POOL_SIZE){}
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

    PGPrepareData(const string& stmt_, const string& query_)
    : stmt(stmt_), query(query_) {}
    PGPrepareData(const PGPrepareData& data)
    : stmt(data.stmt), query(data.query)
    , oids(data.oids){}

    PGPrepareData& add_param_oid(unsigned int oid) {
        oids.push_back(oid);
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
       uint32_t trans_wait_time = DEFAULT_WAIT_TIME,
       uint32_t retransmit_interval = DEFAULT_RET_INTERVAL,
       uint32_t reconnect_interval = DEFAULT_REC_INTERVAL,
       uint32_t batch_size = DEFAULT_BATCH_SIZE,
       uint32_t batch_timeout = DEFAULT_BATCH_TIMEOUT,
       uint32_t max_queue_length = DEFAULT_MAX_Q_LEN)
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

class PGQueryData
{
public:
    string worker_name;
    string query;
    bool   single;
    string sender_id;

    string token;

    PGQueryData(const string& name_, const string& query_,
                bool single, const string& session_id = string(),
                const string& token_ = string())
    : worker_name(name_)
    , query(query_)
    , single(single)
    , sender_id(session_id)
    , token(token_){}
};

class PGTransactionData
{
public:
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

    bool is_db;

    PGTransactionData() : is_db(false), il(read_committed), wp(write_policy::read_only){}
    PGTransactionData(isolation_level il_, write_policy wp_) : is_db(true), il(il_), wp(wp_){}
};

class PGExecute : public PGEvent
{
public:
    PGQueryData qdata;
    PGTransactionData tdata;

    PGExecute(const PGQueryData& qdata_, const PGTransactionData& tdata_)
    : PGEvent(SimpleExecute), qdata(qdata_), tdata(tdata_){}
};

class PGParamExecute : public PGEvent
{
public:
    PGQueryData qdata;
    PGTransactionData tdata;
    vector<AmArg> params;
    bool prepared;

    PGParamExecute(const PGQueryData& qdata_, const PGTransactionData& tdata_, bool prepared_)
    : PGEvent(ParamExecute), qdata(qdata_), tdata(tdata_), prepared(prepared_){}

    template<typename T>
    PGParamExecute& addParam(const T& param){
        params.emplace_back(param);
        return *this;
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
    string stmt;
    PGQueryData qdata;

    vector<AmArg> params;

    PGPrepareExec(const PGQueryData& qdata_, const string& stmt_)
    : PGEvent(PrepareExec), qdata(qdata_), stmt(stmt_){}

    template<typename T>
    PGPrepareExec& addParam(const T& param) {
        params.emplace_back(param);
        return *this;
    }
};

class PGResponse : public PGEvent
{
public:
    string query;
    string token;
    AmArg result;

    PGResponse(const string& query_, const AmArg& res, const string& token_)
    : PGEvent(Result), query(query_), token(token_), result(res){}
};

class PGResponseError : public PGEvent
{
public:
    string query;
    string token;
    string error;

    PGResponseError(const string& query_, const string& res, const string& token_)
    : PGEvent(ResultError), query(query_), token(token_), error(res) {}
};

class PGTimeout : public PGEvent
{
public:
    string query;
    string token;
    PGTimeout(const string& query_, const string& token_)
    : PGEvent(Timeout), query(query_), token(token_) {}
};

#endif/*POSTGRESQL_API_H*/

#ifndef PQ_QUERY_H
#define PQ_QUERY_H

#include "PolicyFactory.h"
#include "Parameter.h"

#include <postgresql/libpq-fe.h>
#include <string>
#include <vector>
#include <AmArg.h>
using std::string;
using std::vector;

class IPGConnection;

class IQuery
{
protected:
    IPGConnection* conn;
    string last_error;
    bool single_mode;
    string query;
    bool is_send;
    bool finished;
public:
    IQuery(const string& q, bool single)
    : conn(0), query(q), single_mode(single)
    , is_send(false), finished(false){}
    virtual ~IQuery(){}

    bool is_single_mode() { return single_mode; }
    bool is_finished() { return is_send || finished; }
    const char* get_last_error() { return last_error.c_str(); }
    string get_query() { return query; }
    void set_finished() { finished = true; }
    void reset(IPGConnection* conn_) { conn = conn_; is_send = false; finished = false; }
    virtual int exec() = 0;
};

struct IPGQuery
{
    IPGQuery(){}
    virtual ~IPGQuery(){}
    virtual int exec() = 0;
    virtual bool is_single_mode() = 0;
    virtual bool is_finished() = 0;
    virtual const char* get_last_error() = 0;
    virtual void reset(IPGConnection* conn) = 0;
    virtual string get_query() = 0;
    virtual uint32_t get_size() = 0;
    virtual IPGQuery* clone() = 0;
    virtual IPGQuery* get_current_query() = 0;
    virtual void set_finished() = 0;
};

class Query : public IPGQuery
{
protected:
    IQuery* impl;
    Query(IQuery* impl) : impl(impl) {}
public:
    Query(const string& cmd, bool single)
    : impl(PolicyFactory::instance()->createQuery(cmd, single)){}
    ~Query(){
        delete impl;
    }

    int exec() override { /*DBG("exec: %s", impl->get_query().c_str()); */return impl->exec(); }
    bool is_single_mode() override { return impl->is_single_mode(); }
    bool is_finished() override { return impl->is_finished(); }
    const char* get_last_error() override { return impl->get_last_error(); }
    void reset(IPGConnection* conn) override { impl->reset(conn); }
    string get_query() override { return impl->get_query(); }
    uint32_t get_size() override { return 1; }
    IPGQuery* clone() override { return new Query(impl->get_query(), impl->is_single_mode()); }
    IPGQuery* get_current_query() override { return this; }
    void set_finished() override { impl->set_finished(); }
};

class QueryParams : public Query
{
    friend class PGQueryParam;
    friend class PGQueryPrepared;
    vector<QueryParam> params;
    bool prepared;
public:
    QueryParams(const string& cmd, bool single, bool prepared)
    : Query(prepared ?
        PolicyFactory::instance()->createQueryPrepared(cmd, single, this):
        PolicyFactory::instance()->createQueryParam(cmd, single, this))
    , prepared(prepared){}
    ~QueryParams() {}
    QueryParams& addParam(const QueryParam& param);
    void addParams(const vector<QueryParam>& params);

    IPGQuery* clone() override {
        QueryParams* q = new QueryParams(impl->get_query(), impl->is_single_mode(), prepared);
        q->addParams(params);
        return q;
    }
};

class Prepared : public Query
{
    string stmt;
    vector<Oid> oids;
public:
    Prepared(const string& stmt,
            const string& cmd, const vector<Oid>& oids)
    : Query(PolicyFactory::instance()->createPrepared(stmt, cmd, oids))
    , stmt(stmt), oids(oids){}
    ~Prepared(){}

    IPGQuery* clone() override {
        return new Prepared(stmt, impl->get_query(), oids);
    }
};

class QueryChain : public IPGQuery
{
    vector<IPGQuery*> childs;
    size_t current;
    bool is_sended;
    bool finished;
    QueryChain()
    : current(0)
    , is_sended(false)
    , finished(false) {}
public:
    QueryChain(IPGQuery* first)
    : is_sended(false)
    , finished(false){
        addQuery(first);
        current = 0;
    }
    ~QueryChain(){
        for(auto& child : childs) delete child;
    }

    int exec() override;
    void addQuery(IPGQuery* q);
    void removeQuery(IPGQuery* q);
    void reset(IPGConnection* conn) override;
    IPGQuery* clone() override;
    IPGQuery* get_current_query() override;

    bool is_single_mode() override { return get_current_query()->is_single_mode(); }
    bool is_finished() override { return is_sended || finished; }
    const char* get_last_error() override { return get_current_query()->get_last_error(); }
    string get_query() override { return get_current_query()->get_query(); }
    void set_finished() override { finished = true; }
    uint32_t get_size() override { return (uint32_t)childs.size(); }
    IPGQuery* get_query(int num) { return childs[num]; }
};

class PGQuery : public IQuery
{
public:
    PGQuery(const string& cmd, bool single)
        : IQuery(cmd, single){}
    virtual ~PGQuery(){}

    int exec() override;
};

class PGQueryParam : public IQuery
{
    QueryParams* parent;
public:
    PGQueryParam(const string& cmd, bool single, QueryParams* parent)
        : IQuery(cmd, single), parent(parent) {}
    virtual ~PGQueryParam(){}

    int exec() override;
};

class PGPrepared : public IQuery
{
    string stmt;
    vector<Oid> oids;
public:
    PGPrepared(const string& stmt,
                const string& cmd, const vector<Oid>& oids)
        : IQuery(cmd, false), stmt(stmt), oids(oids){}
    virtual ~PGPrepared(){}

    int exec() override;
};

class PGQueryPrepared : public IQuery
{
    QueryParams* parent;
public:
    PGQueryPrepared(const string& stmt, bool single, QueryParams* parent)
        : IQuery(stmt, single), parent(parent){}
    virtual ~PGQueryPrepared(){}

    int exec() override;
};

class MockQuery : public IQuery
{
public:
    MockQuery(const string& cmd, bool single)
        : IQuery(cmd, single){}
    virtual ~MockQuery(){}

    int exec() override { is_send = true; return 1; }
};

#endif/*PQ_QUERY_H*/

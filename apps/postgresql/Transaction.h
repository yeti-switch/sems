#pragma once

#include <AmArg.h>
#include <PostgreSqlAPI.h>
#include "PolicyFactory.h"
#include "Query.h"

#include <postgresql/libpq-fe.h>
#include <string>
using std::string;

class IPGConnection;
class IPGTransaction;

struct ITransactionHandler
{
    virtual ~ITransactionHandler(){}
    virtual void onCancel(IPGTransaction* conn) = 0;
    virtual void onError(IPGTransaction* trans, const string& error) = 0;
    virtual void onPQError(IPGTransaction* conn, const string& error) = 0;
    virtual void onFinish(IPGTransaction* conn, const AmArg& result) = 0;
    virtual void onTuple(IPGTransaction* conn, const AmArg& result) = 0;
};

class ITransaction
{
protected:
    friend class IPGTransaction;
    template<PGTransactionData::isolation_level, PGTransactionData::write_policy> friend class DbTransaction;
    friend class PreparedTransaction;
    friend class NonTransaction;
    friend class ConfigTransaction;
    IPGConnection* conn;
    IPGQuery* query;
    AmArg result;
    PGTransactionStatusType status;
    IPGTransaction* parent;
    TransactionType type;
    bool sync_sended;
    bool synced;

    virtual bool check_trans() = 0;
    virtual bool cancel_trans() = 0;
    virtual void fetch_result() = 0;
    virtual void reset(IPGConnection* conn);
public:
    ITransaction(IPGTransaction* p, TransactionType t)
    : conn(0), query(0), parent(p), type(t), synced(false), sync_sended(false) {}
    virtual ~ITransaction() {
        if(query)
            delete query;
    }

    bool is_pipeline();
    bool is_synced() { return synced; }
};

class IPGTransaction
{
public:
    enum DbState {
        BEGIN,
        BODY,
        END
    };

    enum Status
    {
        ACTIVE,
        CANCELING,
        ERROR,
        FINISH
    };
    ITransactionHandler* handler;
protected:
    ITransaction* tr_impl;
    Status status;
    DbState state;

    virtual int begin() { state = BODY; return 1; }
    virtual int end() { state = END; return 1; }
    virtual int rollback() { state = END; return 1; }
    virtual int execute();
    virtual bool is_finished() { return is_pipeline() ? tr_impl->is_synced() : tr_impl->query->is_finished(); }
    virtual bool is_equal(IPGTransaction* trans) { return trans->get_type() == get_type(); }
    virtual IPGTransaction* make_clone() = 0;
    virtual PGTransactionData policy() = 0;

    IPGTransaction(ITransaction* impl, ITransactionHandler* handler)
        : tr_impl(impl), handler(handler), status(ACTIVE), state(BEGIN) {}
public:
    virtual ~IPGTransaction() { delete tr_impl; }

    void check();
    bool exec(IPGQuery* query);
    bool cancel();
    void reset(IPGConnection* conn);
    bool merge(IPGTransaction* trans);
    IPGTransaction* clone() { return make_clone(); }
    IPGQuery* get_query() { return tr_impl->query; }
    PGTransactionData get_policy() { return policy(); }
    bool is_pipeline() { return tr_impl->is_pipeline(); }

    const AmArg& get_result() { return tr_impl->result; }
    Status get_status() { return status; }
    DbState get_state() { return state; }
    IPGConnection* get_conn() { return tr_impl->conn; }
    TransactionType get_type() { return tr_impl->type; }
    uint32_t get_size() { return tr_impl->query->get_size(); }
};

class PGTransaction : public ITransaction
{
    bool check_trans() override;
    bool cancel_trans() override;
    void fetch_result() override;
    void make_result(PGresult* res, bool single);
public:
    PGTransaction(IPGTransaction* h, TransactionType t);
    virtual ~PGTransaction();
};

class MockTransaction : public ITransaction
{
    IPGQuery* last_query;
    size_t current_query_number;
protected:
    TestServer* server;
    bool check_trans() override;
    bool cancel_trans() override;
    void fetch_result() override;
    void reset(IPGConnection* conn) override;
public:
    MockTransaction(IPGTransaction* handler, TransactionType type, TestServer* server_);
    virtual ~MockTransaction();
};

class DbMockTransaction : public MockTransaction
{
    bool check_trans() override;
public:
    DbMockTransaction(IPGTransaction* handler, TestServer* server_);
    virtual ~DbMockTransaction();
};

class NonTransaction : public IPGTransaction
{
    IPGTransaction* make_clone() override {
        return new NonTransaction(*this);
    }
    PGTransactionData policy() override { return PGTransactionData(); }
public:
    NonTransaction(ITransactionHandler* handler)
    : IPGTransaction(PolicyFactory::instance()->createTransaction(this, TR_NON), handler){}
    NonTransaction(const NonTransaction& trans);
    ~NonTransaction(){}
};

template<PGTransactionData::isolation_level isolation, PGTransactionData::write_policy rw>
class DbTransaction : public IPGTransaction
{
    static const char* begin_cmd;
    PGTransactionData::isolation_level il;
    PGTransactionData::write_policy wp;
    int begin() override;
    int execute() override;
    int rollback() override;
    int end() override;
    bool is_equal(IPGTransaction* trans) override;
    bool is_finished() override {
        return IPGTransaction::is_finished() && state == END;
    }
    IPGTransaction* make_clone() override {
        return new DbTransaction<isolation, rw>(*this);
    }
    PGTransactionData policy() override { return PGTransactionData(il, wp); }

public:
    DbTransaction(ITransactionHandler* handler)
    : IPGTransaction(PolicyFactory::instance()->createTransaction(this, TR_POLICY), handler)
    , il(isolation), wp(rw) {}
    DbTransaction(const DbTransaction<isolation, rw>& trans);
    ~DbTransaction(){};
};

extern template class DbTransaction<PGTransactionData::read_committed, PGTransactionData::write_policy::read_write>;
extern template class DbTransaction<PGTransactionData::read_committed, PGTransactionData::write_policy::read_only>;
extern template class DbTransaction<PGTransactionData::repeatable_read, PGTransactionData::write_policy::read_write>;
extern template class DbTransaction<PGTransactionData::repeatable_read, PGTransactionData::write_policy::read_only>;
extern template class DbTransaction<PGTransactionData::serializable, PGTransactionData::write_policy::read_write>;
extern template class DbTransaction<PGTransactionData::serializable, PGTransactionData::write_policy::read_only>;

IPGTransaction* createDbTransaction(ITransactionHandler* handler,
                                    PGTransactionData::isolation_level il,
                                    PGTransactionData::write_policy wp);

class PreparedTransaction : public IPGTransaction
{
    IPGTransaction* make_clone() override {
        return new PreparedTransaction(*this);
    }
    PGTransactionData policy() override { return PGTransactionData(); }
public:
    PreparedTransaction(const string& stmt,
            const string& cmd, const vector<Oid>& oids,
            ITransactionHandler* handler);
    PreparedTransaction(const map<string, PGPrepareData>& prepareds, 
                        ITransactionHandler* handler);
    PreparedTransaction(const PGPrepareExec& prepareds, 
                        ITransactionHandler* handler);
    PreparedTransaction(const PreparedTransaction& trans);
    ~PreparedTransaction(){}
};

class ConfigTransaction : public IPGTransaction
{
    IPGTransaction* make_clone() override {
        return new ConfigTransaction(*this);
    }
    PGTransactionData policy() override { return PGTransactionData(); }
public:
    ConfigTransaction(const map<string, PGPrepareData>& prepareds,
                      const vector<string>& search_pathes,
                      const vector< std::unique_ptr<IPGQuery> > &init_queries,
                      ITransactionHandler* handler);
    ConfigTransaction(const ConfigTransaction& trans);
    ~ConfigTransaction(){}
};

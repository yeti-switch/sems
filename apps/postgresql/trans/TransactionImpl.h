#pragma once

#include "ampi/PostgreSqlAPI.h"
#include "../query/Query.h"

class Connection;
class Transaction;

class TransactionImpl {
  protected:
    friend class Transaction;
    template <PGTransactionData::isolation_level, PGTransactionData::write_policy> friend class DbTransaction;
    friend class PreparedTransaction;
    friend class NonTransaction;
    friend class ConfigTransaction;

    Connection             *conn;
    IQuery                 *query;
    AmArg                   result;
    PGTransactionStatusType status;
    Transaction            *parent;
    TransactionType         type;
    bool                    sync_sent;
    bool                    synced;
    bool                    pipeline_aborted;

    virtual bool check_trans()  = 0;
    virtual bool cancel_trans() = 0;
    virtual int  fetch_result() = 0;
    virtual bool sync_pipeline();
    virtual void reset(Connection *conn);

  public:
    TransactionImpl(Transaction *p, TransactionType t)
        : conn(0)
        , query(0)
        , parent(p)
        , type(t)
        , sync_sent(false)
        , synced(false)
        , pipeline_aborted(false)
    {
    }

    virtual ~TransactionImpl()
    {
        if (query)
            delete query;
    }

    bool is_pipeline();
    bool is_synced() { return synced; }
    bool is_pipeline_aborted() { return pipeline_aborted; }
};

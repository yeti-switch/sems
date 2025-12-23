#pragma once

#include "Transaction.h"
#include "PGTransactionImpl.h"
#include "../query/QueryParams.h"

#include <ampi/PostgreSqlAPI.h>


template <PGTransactionData::isolation_level isolation, PGTransactionData::write_policy rw>
class DbTransaction : public Transaction {
    static const char                 *begin_cmd;
    QueryParams                        dummyParent;
    PGTransactionData::isolation_level il;
    PGTransactionData::write_policy    wp;
    int                                begin() override;
    int                                execute() override;
    int                                rollback() override;
    int                                end() override;
    bool                               is_equal(Transaction *trans) override;
    IQuery                            *get_current_query(bool parent) override;
    bool                               is_finished() override
    {
        return Transaction::is_finished() && state == END && !tr_impl->is_pipeline_aborted();
    }
    Transaction      *make_clone() override { return new DbTransaction<isolation, rw>(*this); }
    PGTransactionData policy() override { return PGTransactionData(il, wp); }

    static Transaction *create(ITransactionHandler *handler, PGTransactionData::isolation_level il,
                               PGTransactionData::write_policy wp);

  public:
    DbTransaction(ITransactionHandler *handler)
        : Transaction(new PGTransactionImpl(this, TR_POLICY), handler)
        , dummyParent("", false, false)
        , il(isolation)
        , wp(rw)
    {
    }
    DbTransaction(const DbTransaction<isolation, rw> &trans);
    ~DbTransaction() {}
};

Transaction *createDbTransaction(ITransactionHandler *handler, PGTransactionData::isolation_level il,
                                 PGTransactionData::write_policy wp);

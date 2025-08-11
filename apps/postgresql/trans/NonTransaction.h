#pragma once

#include "Transaction.h"

class NonTransaction : public Transaction {
    Transaction      *make_clone() override { return new NonTransaction(*this); }
    PGTransactionData policy() override { return PGTransactionData(); }

  public:
    NonTransaction(ITransactionHandler *handler)
        : Transaction(PolicyFactory::instance()->createTransaction(this, TR_NON), handler)
    {
    }
    NonTransaction(const NonTransaction &trans);
    ~NonTransaction() {}
};

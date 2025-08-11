#pragma once

#include "Transaction.h"

#include <ampi/PostgreSqlAPI.h>

class PreparedTransaction : public Transaction {
    Transaction      *make_clone() override { return new PreparedTransaction(*this); }
    PGTransactionData policy() override { return PGTransactionData(); }

  public:
    PreparedTransaction(const string &stmt, const string &cmd, const vector<Oid> &oids, ITransactionHandler *handler);
    PreparedTransaction(const map<string, PGPrepareData> &prepareds, ITransactionHandler *handler);
    PreparedTransaction(const PGPrepareExec &prepareds, ITransactionHandler *handler);
    PreparedTransaction(const PreparedTransaction &trans);
    ~PreparedTransaction() {}
};

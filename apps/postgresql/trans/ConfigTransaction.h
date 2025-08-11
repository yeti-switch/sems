#pragma once

#include "Transaction.h"

class ConfigTransaction : public Transaction {
    Transaction      *make_clone() override { return new ConfigTransaction(*this); }
    PGTransactionData policy() override { return PGTransactionData(); }

  public:
    ConfigTransaction(const map<string, PGPrepareData> &prepareds, const vector<string> &search_pathes,
                      const vector<std::unique_ptr<IQuery>> &init_queries, ITransactionHandler *handler);
    ConfigTransaction(const ConfigTransaction &trans);
    ~ConfigTransaction() {}
};

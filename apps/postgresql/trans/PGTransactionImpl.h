#pragma once

#include "TransactionImpl.h"

class PGTransactionImpl
  : public TransactionImpl
{
    bool check_trans() override;
    bool cancel_trans() override;
    int fetch_result() override;
    void make_result(PGresult* res, bool single);

  public:
    PGTransactionImpl(Transaction* h, TransactionType t);
    virtual ~PGTransactionImpl();
};

#pragma once

#include "TransactionImpl.h"

class MockTransactionImpl
  : public TransactionImpl
{
    IQuery* last_query;
    size_t current_query_number;

  protected:
    TestServer* server;
    bool check_trans() override;
    bool cancel_trans() override;
    int fetch_result() override;
    void reset(Connection* conn) override;

  public:
    MockTransactionImpl(Transaction* handler, TransactionType type, TestServer* server_);
    virtual ~MockTransactionImpl();
};

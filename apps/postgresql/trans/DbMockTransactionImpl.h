#pragma once

#include "MockTransactionImpl.h"

class DbMockTransactionImpl
  : public MockTransactionImpl
{
    bool check_trans() override;
    int fetch_result() override;
public:
    DbMockTransactionImpl(Transaction* handler, TestServer* server_);
    virtual ~DbMockTransactionImpl();
};

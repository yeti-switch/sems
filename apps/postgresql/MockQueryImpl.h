#pragma once

#include "IQueryImpl.h"

class MockQueryImpl : public IQueryImpl
{
public:
    MockQueryImpl(const string& cmd, bool single)
        : IQueryImpl(cmd, single){}
    virtual ~MockQueryImpl(){}

    int exec() override { is_send = true; return 1; }
};

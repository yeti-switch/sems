#pragma once

#include "IQueryImpl.h"

class MockQueryImpl : public IQueryImpl
{
public:
    MockQueryImpl(const string& cmd, bool single)
        : IQueryImpl(cmd, single){}
    virtual ~MockQueryImpl(){}

    int exec() override {
        uint64_t u;
        is_send = write(conn->getSocket(), &u, sizeof(u)) == sizeof(u);
        return 1;
    }
};

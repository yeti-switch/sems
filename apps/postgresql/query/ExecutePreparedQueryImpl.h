#pragma once

#include "IQueryImpl.h"
#include "QueryParams.h"

class ExecutePreparedQueryImpl : public IQueryImpl
{
    QueryParams* parent;
public:
    ExecutePreparedQueryImpl(const string& stmt, bool single, QueryParams* parent)
        : IQueryImpl(stmt, single), parent(parent){}
    virtual ~ExecutePreparedQueryImpl(){}

    int exec() override;
};

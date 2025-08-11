#pragma once

#include "IQueryImpl.h"
#include "QueryParams.h"

class ParameterizedQueryImpl : public IQueryImpl {
    QueryParams *parent;

  public:
    ParameterizedQueryImpl(const string &cmd, bool single, QueryParams *parent)
        : IQueryImpl(cmd, single)
        , parent(parent)
    {
    }
    virtual ~ParameterizedQueryImpl() {}

    int exec() override;
};

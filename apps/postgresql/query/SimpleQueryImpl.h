#pragma once

#include "IQueryImpl.h"

class SimpleQueryImpl : public IQueryImpl {
  public:
    SimpleQueryImpl(const std::string &cmd, bool single)
        : IQueryImpl(cmd, single)
    {
    }
    virtual ~SimpleQueryImpl() {}

    int exec() override;
};

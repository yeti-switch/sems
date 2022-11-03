#pragma once

#include "IQueryImpl.h"

#include <postgresql/libpq-fe.h>

#include <string>
using std::string;
#include <vector>
using std::vector;

class PrepareQueryImpl : public IQueryImpl
{
    string stmt;
    vector<Oid> oids;

  public:
    PrepareQueryImpl(const string& stmt,
               const string& cmd, const vector<Oid>& oids)
     : IQueryImpl(cmd, false), stmt(stmt), oids(oids){}
    virtual ~PrepareQueryImpl(){}

    int exec() override;
};

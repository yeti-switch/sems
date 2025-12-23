#pragma once

#include "Query.h"
#include <string>

using std::vector;

class QueryPrepare : public Query {
    std::string stmt;
    vector<Oid> oids;

  public:
    QueryPrepare(const string &stmt, const string &cmd, const vector<Oid> &oids);
    ~QueryPrepare() {}

    IQuery *clone() override { return new QueryPrepare(stmt, impl->get_query(), oids); }
};

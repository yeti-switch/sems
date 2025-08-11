#pragma once

#include "Query.h"
#include <string>

class QueryPrepare : public Query {
    std::string stmt;
    vector<Oid> oids;

  public:
    QueryPrepare(const string &stmt, const string &cmd, const vector<Oid> &oids)
        : Query(PolicyFactory::instance()->createPrepared(stmt, cmd, oids))
        , stmt(stmt)
        , oids(oids)
    {
    }
    ~QueryPrepare() {}

    IQuery *clone() override { return new QueryPrepare(stmt, impl->get_query(), oids); }
};

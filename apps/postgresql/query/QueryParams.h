#pragma once

#include "Query.h"

class QueryParams : public Query {
    friend class ParameterizedQueryImpl;
    friend class ExecutePreparedQueryImpl;
    vector<QueryParam> params;
    bool               prepared;

  public:
    QueryParams(const string &cmd, bool single, bool prepared)
        : Query(prepared ? PolicyFactory::instance()->createQueryPrepared(cmd, single, this)
                         : PolicyFactory::instance()->createQueryParam(cmd, single, this))
        , prepared(prepared)
    {
    }
    ~QueryParams() {}
    QueryParams &addParam(const QueryParam &param);
    void         addParams(const vector<QueryParam> &params);

    void getParams(AmArg &params);

    IQuery *clone() override
    {
        QueryParams *q = new QueryParams(impl->get_query(), impl->is_single_mode(), prepared);
        q->addParams(params);
        return q;
    }
};

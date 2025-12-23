#pragma once

#include "Query.h"

using std::vector;

class QueryParams : public Query {
    friend class ParameterizedQueryImpl;
    friend class ExecutePreparedQueryImpl;
    vector<QueryParam> params;
    bool               prepared;

  public:
    QueryParams(const string &cmd, bool single, bool prepared);
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

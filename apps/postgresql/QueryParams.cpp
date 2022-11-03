#include "QueryParams.h"

QueryParams& QueryParams::addParam(const QueryParam& param)
{
    params.push_back(param);
    return *this;
}

void QueryParams::addParams(const vector<QueryParam>& params_)
{
    params = params_;
}

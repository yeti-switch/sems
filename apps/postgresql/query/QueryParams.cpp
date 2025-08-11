#include "QueryParams.h"

QueryParams &QueryParams::addParam(const QueryParam &param)
{
    params.push_back(param);
    return *this;
}

void QueryParams::addParams(const vector<QueryParam> &params_)
{
    params = params_;
}

void QueryParams::getParams(AmArg &ret)
{
    ret.assertArray();
    for (auto &p : params) {
        AmArg param;
        param["oid"]    = p.get_oid();
        param["binary"] = p.is_binary_format();
        param["value"]  = get_result(p.get_oid(), p.is_binary_format(), p.get_value());
        param["size"]   = p.get_length();
        ret.push(param);
    }
}

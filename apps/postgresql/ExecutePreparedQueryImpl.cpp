#include "ExecutePreparedQueryImpl.h"

#include "IQueryImpl.h"
#include "Connection.h"

int ExecutePreparedQueryImpl::exec()
{
    if(!conn) {
        last_error = "absent connection";
        return -1;
    }

    bool ret = false;
    is_send = false;
    vector<const char*> values;
    vector<int> lengths;
    vector<int> formats;
    for(auto& param : parent->params) {
        values.push_back(param.get_value());
        lengths.push_back(param.get_length());
        formats.push_back(param.is_binary_format());
    }
    ret = is_send = PQsendQueryPrepared(*conn, query.c_str(),
                                      parent->params.size(), values.data(),
                                      lengths.data(), formats.data(), 0);
    if(!ret) last_error = PQerrorMessage(*conn);
    if(is_send && single_mode) {
        ret = PQsetSingleRowMode(*conn);
        if(!ret) last_error = PQerrorMessage(*conn);
    }
    return ret ? 1 : -1;
}

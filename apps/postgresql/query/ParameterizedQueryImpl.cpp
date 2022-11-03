#include "ParameterizedQueryImpl.h"
#include "../conn/Connection.h"

#include <postgresql/libpq-fe.h>

int ParameterizedQueryImpl::exec()
{
    if(!conn) {
        last_error = "absent connection";
        return -1;
    }

    bool ret = false;
    is_send = false;
    vector<unsigned int> oids;
    vector<const char*> values;
    vector<int> lengths;
    vector<int> formats;
    for(auto& param : parent->params) {
        oids.push_back(param.get_oid());
        values.push_back(param.get_value());
        lengths.push_back(param.get_length());
        formats.push_back(param.is_binary_format());
    }
    ret = is_send = PQsendQueryParams(*conn, query.c_str(),
                                      parent->params.size(), oids.data(), values.data(),
                                      lengths.data(), formats.data(), 0);
    if(!ret) last_error = PQerrorMessage(*conn);
    if(is_send && single_mode) {
        ret = PQsetSingleRowMode(*conn);
        if(!ret) last_error = PQerrorMessage(*conn);
    }
    return ret ? 1 : -1;
}

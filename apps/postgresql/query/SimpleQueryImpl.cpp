#include "SimpleQueryImpl.h"
#include "../conn/Connection.h"

#include <postgresql/libpq-fe.h>

int SimpleQueryImpl::exec()
{
    if(!conn) {
        last_error = "absent connection";
        return -1;
    }
    bool ret = false;
    is_send = false;
    ret = is_send = PQsendQuery(*conn, query.c_str());
    if(!ret) last_error = PQerrorMessage(*conn);
    if(is_send && single_mode) {
        ret = PQsetSingleRowMode(*conn);
        if(!ret) last_error = PQerrorMessage(*conn);
    }
    return ret ? 1 : -1;
}

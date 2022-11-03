#include "PrepareQueryImpl.h"
#include "Connection.h"

#include <postgresql/libpq-fe.h>

int PrepareQueryImpl::exec()
{
    if(!conn) {
        last_error = "absent connection";
        return -1;
    }

    bool ret = is_send = PQsendPrepare(*conn, stmt.c_str(), query.c_str(), oids.size(), oids.data());
    if(!ret) last_error = PQerrorMessage(*conn);
    return ret ? 1 : -1;
}

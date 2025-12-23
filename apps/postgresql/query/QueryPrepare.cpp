#include "QueryPrepare.h"
#include "PrepareQueryImpl.h"

QueryPrepare::QueryPrepare(const string &stmt, const string &cmd, const vector<Oid> &oids)
    : Query(new PrepareQueryImpl(stmt, cmd, oids))
    , stmt(stmt)
    , oids(oids)
{
}

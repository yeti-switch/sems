#include "Query.h"
#include "../conn/Connection.h"
#include "../trans/Transaction.h"
#include "SimpleQueryImpl.h"

Query::Query(IQueryImpl *impl)
    : impl(impl)
{
}

Query::Query(const string &cmd, bool single)
    : impl(new SimpleQueryImpl(cmd, single))
{
}

Query::~Query()
{
    delete impl;
}

int Query::exec()
{
    TRANS_LOG(getConnection()->getCurrentTransaction(), "exec: %s", impl->get_query().c_str());
    return impl->exec();
}

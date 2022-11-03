#include "Query.h"
#include "Connection.h"
#include "Transaction.h"

int Query::exec()
{
    TRANS_LOG(getConnection()->getCurrentTransaction(), "exec: %s", impl->get_query().c_str());
    return impl->exec();
}

#include "TransactionImpl.h"

#include "Connection.h"

void TransactionImpl::reset(Connection *conn_)
{
    conn = conn_;
    synced = false;
    sync_sent = false;
    pipeline_aborted = false;
    query->reset(conn);
}

bool TransactionImpl::is_pipeline()
{
    return conn->getPipeStatus() == PQ_PIPELINE_ON;
}

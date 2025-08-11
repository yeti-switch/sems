#include "MockTransactionImpl.h"

#include "Transaction.h"
#include "../conn/Connection.h"
#include "../query/QueryChain.h"

MockTransactionImpl::MockTransactionImpl(Transaction *h, TransactionType t, TestServer *server_)
    : TransactionImpl(h, t)
    , last_query(0)
    , current_query_number(0)
    , server(server_)
{
    status = PQTRANS_IDLE;
}

MockTransactionImpl::~MockTransactionImpl() {}

bool MockTransactionImpl::check_trans()
{
    Query      *single = dynamic_cast<Query *>(query);
    QueryChain *chain  = dynamic_cast<QueryChain *>(query);
    string      query_;
    if (single) {
        query_ = single->get_query();
    } else if (chain) {
        if (current_query_number < query->get_size()) {
            query_ = chain->get_query(current_query_number)->get_query();
        }
    } else {
        ERROR("unknown query");
        return true;
    }

    if ((status == PQTRANS_IDLE && query->is_finished()) || status == PQTRANS_ACTIVE) {
        status = PQTRANS_ACTIVE;
        return !server->checkTail(query_);
    }
    if (status == PQTRANS_INERROR && !synced) {
        synced = true;
        query->set_finished();
    } else if (status == PQTRANS_INERROR && synced) {
        status = PQTRANS_IDLE;
    }

    return true;
}

int MockTransactionImpl::fetch_result()
{
    Query      *single = dynamic_cast<Query *>(query);
    QueryChain *chain  = dynamic_cast<QueryChain *>(query);
    string      query_;
    if (single) {
        query_ = single->get_query();
    } else if (chain) {
        if (current_query_number < query->get_size()) {
            query_ = chain->get_query(current_query_number)->get_query();
        }
    } else {
        ERROR("unknown query");
        return 0;
    }

    server->clearTail(query_);
    if (!is_pipeline()) {
        status = PQTRANS_IDLE;
        string errorcode;
        if (server->isError(query_, errorcode)) {
            parent->handler->onError(parent, "mock error");
            if (!errorcode.empty()) {
                parent->handler->onErrorCode(parent, errorcode);
            }
        } else {
            AmArg res;
            while (server->getResponse(query_, res)) {
                result.push(res);
            }
        }
    } else if (current_query_number < query->get_size()) {
        string errorcode;
        if (server->isError(query_, errorcode)) {
            parent->handler->onError(parent, "mock error");
            if (!errorcode.empty()) {
                parent->handler->onErrorCode(parent, errorcode);
            }
            status = PQTRANS_INERROR;
        } else {
            AmArg res;
            while (server->getResponse(query_, res)) {
                result.push(res);
            }
        }
        current_query_number++;
        query->put_result();
    } else {
        if (server->isSyncError()) {
            parent->handler->onError(parent, "sync error");
            status = PQTRANS_INERROR;
        } else {
            synced = true;
            status = PQTRANS_IDLE;
        }
    }

    return 0;
}

void MockTransactionImpl::reset(Connection *conn)
{
    last_query           = 0;
    current_query_number = 0;
    TransactionImpl::reset(conn);
}

bool MockTransactionImpl::cancel_trans()
{
    return true;
}

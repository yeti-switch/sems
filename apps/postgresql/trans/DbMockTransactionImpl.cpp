#include "DbMockTransactionImpl.h"

#include "Transaction.h"

DbMockTransactionImpl::DbMockTransactionImpl(Transaction* handler, TestServer* server_)
  : MockTransactionImpl(handler, TR_POLICY, server_)
{}

DbMockTransactionImpl::~DbMockTransactionImpl()
{}

int DbMockTransactionImpl::fetch_result()
{
    if(current_query_number == 0 && query->get_result_got() == 0) {
        query->put_result();
    }
    return MockTransactionImpl::fetch_result();
}

bool DbMockTransactionImpl::check_trans()
{
    if(status == PQTRANS_IDLE && query->get_current_query()->is_finished()) {
        string error_code;
        if(parent->get_state() == Transaction::BODY && server->isError(query->get_query(), error_code)) {
            status = PQTRANS_INERROR;
            parent->handler->onError(parent, "mock error");
            if(!error_code.empty()) {
                parent->handler->onErrorCode(parent, error_code);
            }
        } else 
            status = PQTRANS_INTRANS;
    } else if(status == PQTRANS_INTRANS ||
              status == PQTRANS_INERROR) {
        status = PQTRANS_ACTIVE;
    }
    return true;
}

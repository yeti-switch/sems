#include "PGTransactionImpl.h"
#include "Transaction.h"

#include "../conn/Connection.h"

#include <postgresql/libpq-fe.h>

#define MAX_BUF_SIZE 256

PGTransactionImpl::PGTransactionImpl(Transaction* h, TransactionType t)
  : TransactionImpl(h, t)
{}

PGTransactionImpl::~PGTransactionImpl()
{}

bool PGTransactionImpl::check_trans()
{
    if(!conn) {
        ERROR("absent connection");
        return false;
    }

    if(conn->getPipeStatus() == PQ_PIPELINE_ON && query->is_finished()) {
        if(conn->flush()) {
            TRANS_LOG(parent, "flush data");
        }
    }

    status = PQtransactionStatus(*conn);

    return !PQisBusy(*conn);
}

bool PGTransactionImpl::cancel_trans()
{
    if(!conn) {
        ERROR("absent connection");
        return true;
    }

    bool ret = true;
    char errbuf[MAX_BUF_SIZE] = {0};
    PGcancel* cancel = PQgetCancel(*conn);
    if(!PQcancel(cancel, errbuf, MAX_BUF_SIZE)) {
        parent->handler->onPQError(parent, errbuf);
        ret = true;
    }
    PQfreeCancel(cancel);
    return ret;
}

void PGTransactionImpl::make_result(PGresult* res, bool single)
{
    int rows = PQntuples(res);
    int fields= PQnfields(res);
    vector<string> field_names;
    vector<Oid> field_types;
    vector<bool> field_format;
    for(int j = 0; j < fields; j++) {
        field_names.push_back(PQfname(res, j));
        field_types.push_back(PQftype(res, j));
        field_format.push_back(PQfformat(res, j));
    }
    for(int i = 0; i < rows; i++) {
        AmArg row;
        for(int j = 0; j < fields; j++) {
            row.push(field_names[j], get_result(
                field_types[j], field_format[j],
                PQgetvalue(res, i, j), PQgetisnull(res, i, j)));
        }
        if(single) parent->handler->onTuple(parent, row);
        result.push(row);
    }
    TRANS_LOG(parent, "result: %s", AmArg::print(result).c_str());
}

int PGTransactionImpl::fetch_result()
{
    if(!conn) {
        ERROR("absent connection");
        return 0;
    }

    PGresult* res = nullptr;
    do {
        if(!res) {
            res = PQgetResult(*conn);
            TRANS_LOG(parent, "PQgetResult(*conn)) = %p", res);
        }
        while(res) {
            bool single = false;
            ExecStatusType st = PQresultStatus(res);
            switch (st) {
            case PGRES_COMMAND_OK:
                TRANS_LOG(parent, "command ok");
                break;
            case PGRES_EMPTY_QUERY:
            case PGRES_BAD_RESPONSE:
            case PGRES_NONFATAL_ERROR:
            case PGRES_FATAL_ERROR: {
                TRANS_LOG(parent, "error");
                char* error = PQresultVerboseErrorMessage(res, PQERRORS_DEFAULT, PQSHOW_CONTEXT_NEVER);
                parent->get_query()->get_current_query()->set_last_error(error);
                parent->handler->onError(parent, error ? error : "");
                char* errorfield = PQresultErrorField(res, PG_DIAG_SQLSTATE);
                parent->handler->onErrorCode(parent, errorfield ? errorfield : "");
                break;
            }
            case PGRES_SINGLE_TUPLE:
                TRANS_LOG(parent, "single tuple");
                single = true;
                [[fallthrough]];
            case PGRES_TUPLES_OK:
                TRANS_LOG(parent, "tuple ok");
                make_result(res, single);
                break;
            case PGRES_PIPELINE_SYNC:
                TRANS_LOG(parent, "pipeline synced");
                synced = true;
                break;
            case PGRES_PIPELINE_ABORTED:
                TRANS_LOG(parent, "pipeline aborted");
                pipeline_aborted = true;
                break;
            default:
                ERROR("unexpected ExecStatusType:%d", st);
            }

            if(!pipeline_aborted && !synced && !single) query->put_result();

            PQclear(res);
            res = PQgetResult(*conn);
            TRANS_LOG(parent, "PQgetResult(*conn)) = %p", res);
        }

        if(PQisBusy(*conn)) {
            TRANS_LOG(parent, "PQisBusy:1. break fetch cycle");
            return 1;
        }

        res = PQgetResult(*conn);
        TRANS_LOG(parent, "PQgetResult(*conn)) = %p", res);
    } while (res);

    return 0;
}

bool PGTransactionImpl::sync_pipeline()
{
    sync_sent = true;
    return conn->syncPipeline();
}

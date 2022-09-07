#include "Transaction.h"
#include "Connection.h"
#include "pqtypes-int.h"
#include <log.h>
#include <netinet/in.h>
#include <jsonArg.h>
#include <AmUtils.h>

#define MAX_BUF_SIZE 256

int IPGTransaction::execute()
{
     if(tr_impl->query->exec() < 0)
         return -1;
     handler->onSend(this);
     return is_pipeline() ? (tr_impl->query->is_finished() ? 1 : 2) : 1;
}

void ITransaction::reset(IPGConnection* conn_)
{
    conn = conn_;
    synced = false;
    query->reset(conn);
}

bool ITransaction::is_pipeline()
{
    return conn->getPipeStatus() == PQ_PIPELINE_ON;
}

bool IPGTransaction::cancel()
{
    if(status == CANCELING) return false;
    if(status == FINISH) return true;
    if(tr_impl->cancel_trans()) {
         status = CANCELING;
         handler->onCancel(this);
         return true;
     }
     return false;
}

void IPGTransaction::check()
{
    bool next;
    do {
        //DBG("IPGTransaction::check() in do while(%u)", next);
        next = false;
        if(tr_impl->query && tr_impl->check_trans()) {
            if(tr_impl->status == PQTRANS_ACTIVE && status != FINISH) {
                //DBG("try fetch result");
                tr_impl->fetch_result();
                if(is_finished()) {
                    status = FINISH;
                    handler->onFinish(this, tr_impl->result);
                }
                next = true;
            } else if((tr_impl->status == PQTRANS_IDLE || tr_impl->status == PQTRANS_INTRANS)
                      && status != FINISH) {
                //DBG("status idle - send query");
                next = is_pipeline();
                int ret = 0;
                // 0 - run transaction request, do not run main query
                // 1 - transaction request is finished, run main query
                // -1 - error
                ret = begin();
                if(ret < 0) handler->onPQError(this, tr_impl->query->get_last_error());
                // 0 - main query finished, run end transaction request
                // 1 - main query sended, do not run end transaction request
                // 2 - main query sending in pipeline mode
                // -1 - error
                do {
                    if(ret) ret = execute();
                    else if(ret < 0) handler->onPQError(this, tr_impl->query->get_last_error());
                    else return;
                } while(ret > 1);
                if(!ret) ret = end();
                if(ret < 0) handler->onPQError(this, tr_impl->query->get_last_error());
            } else if(tr_impl->status == PQTRANS_INERROR) {
                //DBG("status aborted - roolback");
                status = ERROR;
                int ret = rollback();
                if(ret < 0) handler->onPQError(this, tr_impl->query->get_last_error());
                if(tr_impl->conn->getPipeStatus() == PQ_PIPELINE_ON)
                    tr_impl->conn->syncPipeline();
            } else if(tr_impl->conn->getPipeStatus() == PQ_PIPELINE_ABORTED){
                //DBG("pipeline aborted");
            }
        } else {
            //DBG("busy break from while");
        }
    } while(next);
}

bool IPGTransaction::exec(IPGQuery* query)
{
    if(tr_impl->query) return false;

    tr_impl->query = query;
    return true;
}

void IPGTransaction::reset(IPGConnection* conn)
{
    status = ACTIVE;
    state = BEGIN;
    if(tr_impl->conn)
        tr_impl->conn->cur_transaction = 0;
    tr_impl->reset(conn);
}

bool IPGTransaction::merge(IPGTransaction* trans)
{ 
    if(!tr_impl->query || !trans->tr_impl->query || !is_equal(trans)) return false;
    QueryChain* chain = dynamic_cast<QueryChain*>(tr_impl->query);
    if(!chain) {
        chain = new QueryChain(tr_impl->query);
        tr_impl->query = chain;
    }
    chain->addQuery(trans->tr_impl->query->clone());
    return true;
}

PGTransaction::PGTransaction(IPGTransaction* h, TransactionType t)
: ITransaction(h, t){}

PGTransaction::~PGTransaction(){}

bool PGTransaction::check_trans()
{
    if(!conn) {
        ERROR("absent connection");
        return true;
    }

    if(conn->getPipeStatus() == PQ_PIPELINE_ON && query->is_finished() && !sync_sent) {
        //DBG("send Sync");
        conn->syncPipeline();
        sync_sent = true;
    }
    status = PQtransactionStatus((PGconn*)conn->get());
    return !PQisBusy((PGconn*)conn->get());
}

bool PGTransaction::cancel_trans()
{
    if(!conn) {
        ERROR("absent connection");
        return true;
    }

    bool ret = true;
    char errbuf[MAX_BUF_SIZE] = {0};
    PGcancel* cancel = PQgetCancel((PGconn*)conn->get());
    if(!PQcancel(cancel, errbuf, MAX_BUF_SIZE)) {
        parent->handler->onPQError(parent, errbuf);
        ret = true;
    }
    PQfreeCancel(cancel);
    return ret;
}

void PGTransaction::make_result(PGresult* res, bool single)
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
    //DBG("result: %s", AmArg::print(result).c_str());
}

void PGTransaction::fetch_result()
{
    if(!conn) {
        ERROR("absent connection");
        return;
    }

    PGresult* res = 0;
    do {
        if(!res) {
            res = PQgetResult((PGconn*)conn->get());
            //DBG("PQgetResult((PGconn*)conn->get())) = %p", res);
        }
        while(res) {
            bool single = false;
            ExecStatusType st = ExecStatusType::PGRES_COMMAND_OK;
            switch ((int)(st = PQresultStatus(res))) {
            case PGRES_EMPTY_QUERY:
            case PGRES_BAD_RESPONSE:
            case PGRES_NONFATAL_ERROR:
            case PGRES_FATAL_ERROR: {
                char* error = PQresultVerboseErrorMessage(res, PQERRORS_DEFAULT, PQSHOW_CONTEXT_NEVER);
                parent->handler->onError(parent, error);
                char* errorfield = PQresultErrorField(res, PG_DIAG_SQLSTATE);
                parent->handler->onErrorCode(parent, errorfield);
                break;
            }
            case PGRES_PIPELINE_ABORTED:
                break;
            case PGRES_SINGLE_TUPLE:
                single = true;
            case PGRES_TUPLES_OK:
                make_result(res, single);
                break;
            case PGRES_PIPELINE_SYNC:
                //DBG("pipeline synced");
                synced = true;
                break;
            }

            PQclear(res);
            res = PQgetResult((PGconn*)conn->get());
            //DBG("PQgetResult((PGconn*)conn->get())) = %p", res);
        }
        res = PQgetResult((PGconn*)conn->get());
        //DBG("PQgetResult((PGconn*)conn->get())) = %p", res);
    } while (res);

}

MockTransaction::MockTransaction(IPGTransaction* h, TransactionType t, TestServer* server_)
  : ITransaction(h, t),
    last_query(0),
    current_query_number(0),
    server(server_)
{
    status = PQTRANS_IDLE;
}

MockTransaction::~MockTransaction() {}

bool MockTransaction::check_trans()
{
    if(status == PQTRANS_IDLE &&
       query->is_finished()) {
        status = PQTRANS_ACTIVE;
    }
    return true;
}

void MockTransaction::fetch_result()
{
    Query* single = dynamic_cast<Query*>(query);
    QueryChain* chain = dynamic_cast<QueryChain*>(query);
    //IPGQuery* cur_query = 0;
    string query_;
    if(single) {
        query_ = single->get_query();
        //cur_query = single;
    } else if(chain) {
        if(current_query_number < query->get_size()) {
            query_ = chain->get_query(current_query_number)->get_query();
            //cur_query = chain->get_query(current_query_number);
        }
    } else {
        ERROR("unknown query");
        return;
    }

    if(!is_pipeline()) {
        status = PQTRANS_IDLE;
        string errorcode;
        if(server->isError(query_, errorcode)) {
            parent->handler->onError(parent, "mock error");
            if(!errorcode.empty()) {
                parent->handler->onErrorCode(parent, errorcode);
            }
        } else {
            AmArg res = server->getResponse(query_);
            if(!isArgUndef(res))
                result.push(res);
        }
    } else if(current_query_number < query->get_size()){
        string errorcode;
        if(server->isError(query_, errorcode)) {
            parent->handler->onError(parent, "mock error");
            if(!errorcode.empty()) {
                parent->handler->onErrorCode(parent, errorcode);
            }
        } else {
            AmArg res = server->getResponse(query_);
            if(!isArgUndef(res))
                result.push(res);
        }
        current_query_number++;
    } else {
        synced = true;
        status = PQTRANS_IDLE;
    }
}

void MockTransaction::reset(IPGConnection* conn)
{
    last_query = 0;
    ITransaction::reset(conn);
}

bool MockTransaction::cancel_trans()
{
    return true;
}

DbMockTransaction::DbMockTransaction(IPGTransaction* handler, TestServer* server_)
: MockTransaction(handler, TR_POLICY, server_){}
DbMockTransaction::~DbMockTransaction(){}
bool DbMockTransaction::check_trans()
{
    if(status == PQTRANS_IDLE && query->get_current_query()->is_finished()) {
        string error_code;
        if(parent->get_state() == IPGTransaction::BODY && server->isError(query->get_query(), error_code)) {
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

NonTransaction::NonTransaction(const NonTransaction& trans)
: IPGTransaction(PolicyFactory::instance()->createTransaction(this, TR_NON), trans.handler) {
    if(trans.tr_impl->query)
        tr_impl->query = trans.tr_impl->query->clone();
}

template<PGTransactionData::isolation_level isolation, PGTransactionData::write_policy rw>
DbTransaction<isolation, rw>::DbTransaction(const DbTransaction<isolation, rw>& trans)
: IPGTransaction(PolicyFactory::instance()->createTransaction(this, TR_POLICY), trans.handler)
, il(isolation), wp(rw), dummyParent("", false, false) {
    if(trans.tr_impl->query)
        tr_impl->query = trans.tr_impl->query->clone();
}

template<PGTransactionData::isolation_level isolation, PGTransactionData::write_policy rw> 
int DbTransaction<isolation, rw>::begin()
{
    if(!get_conn()) {
        ERROR("absent connection");
        return -1;
    }
    if(state == BEGIN) {
        IQuery* begin_q = PolicyFactory::instance()->createQueryParam(begin_cmd, false, &dummyParent);
        begin_q->reset(get_conn());
        int ret = begin_q->exec();
        delete begin_q;
        state = BODY;
        //DBG("exec: %s", begin_cmd);
        return ret > 0 ? is_pipeline() : -1;
    }
    return 1;
}

template<PGTransactionData::isolation_level isolation, PGTransactionData::write_policy rw>
int DbTransaction<isolation, rw>::execute()
{
    if(!tr_impl->query->is_finished()) {
        int ret = IPGTransaction::execute();
        if(ret  < 0) return -1;
        else if(ret == 1 && is_pipeline()) return 0;
        else return ret;
    } else {
        return 0;
    }
}

template<PGTransactionData::isolation_level isolation, PGTransactionData::write_policy rw>
int DbTransaction<isolation, rw>::rollback()
{
    if(!get_conn()) {
        ERROR("absent connection");
        return -1;
    }
    if(state != BEGIN) {
        IQuery* end_q = PolicyFactory::instance()->createQueryParam("ROLLBACK", false, &dummyParent);
        end_q->reset(get_conn());
        int ret = end_q->exec();
        delete end_q;
        state = END;
        if(ret) tr_impl->query->set_finished();
        //DBG("exec: ROLLBACK");
        return ret ? 0 : -1;
    }
    return 1;
}

template<PGTransactionData::isolation_level isolation, PGTransactionData::write_policy rw>
bool DbTransaction<isolation, rw>::is_equal(IPGTransaction* trans)
{
    if(trans->get_type() == TR_POLICY) {
        DbTransaction<isolation, rw>* dbtrans = (DbTransaction<isolation, rw>*)trans;
        return dbtrans->il == il && dbtrans->wp == wp;
    } else if(IPGTransaction::is_equal(trans)) return true;
    return false;
}

template<PGTransactionData::isolation_level isolation, PGTransactionData::write_policy rw>
int DbTransaction<isolation, rw>::end()
{
    if(!get_conn()) {
        ERROR("absent connection");
        return -1;
    }
    if(state == BODY) {
        IQuery* end_q = PolicyFactory::instance()->createQueryParam("END", false, &dummyParent);
        end_q->reset(get_conn());
        int ret = end_q->exec();
        delete end_q;
        state = END;
        //DBG("exec: END");
        return ret ? 0 : -1;
    }
    return 1;
}

PreparedTransaction::PreparedTransaction(const std::string& stmt,
                   const std::string& cmd, const vector<Oid>& oids,
                   ITransactionHandler* handler)
: IPGTransaction(PolicyFactory::instance()->createTransaction(this, TR_PREPARED), handler)
{
    exec(new Prepared(stmt, cmd, oids));
}

PreparedTransaction::PreparedTransaction(const map<string, PGPrepareData>& prepareds,
                                        ITransactionHandler* handler)
: IPGTransaction(PolicyFactory::instance()->createTransaction(this, TR_PREPARED), handler)
{
    if(prepareds.empty()) {
        ERROR("prepared list is empty");
        return;
    }
    auto first = prepareds.begin();
    QueryChain* query = new QueryChain(new Prepared(first->first, first->second.query, first->second.oids));
    for(auto it = ++first; it != prepareds.end(); it++) {
        query->addQuery(new Prepared(it->first, it->second.query, it->second.oids));
    }
    exec(query);
}

PreparedTransaction::PreparedTransaction(const PGPrepareExec& prepared,
                                         ITransactionHandler* handler)
: IPGTransaction(PolicyFactory::instance()->createTransaction(this, TR_PREPARED), handler)
{
    QueryParams* qexec = new QueryParams(prepared.stmt, prepared.info.single, true);
    vector<QueryParam> qparams = getParams(prepared.info.params);
    vector<unsigned int> oids;
    for(auto& param : qparams) {
        oids.push_back(param.get_oid());
        qexec->addParam(param);
    }
    QueryChain* query = new QueryChain(new Prepared(prepared.stmt, prepared.info.query, oids));
    query->addQuery(qexec);
    exec(query);
}

PreparedTransaction::PreparedTransaction(const PreparedTransaction& trans)
: IPGTransaction(PolicyFactory::instance()->createTransaction(this, TR_PREPARED), trans.handler)
{
    if(trans.tr_impl->query)
        tr_impl->query = trans.tr_impl->query->clone();
}

ConfigTransaction::ConfigTransaction(const map<std::string, PGPrepareData>& prepareds,
                                     const vector<std::string>& search_pathes,
                                     const vector< std::unique_ptr<IPGQuery> > &init_queries,
                                     ITransactionHandler* handler)
: IPGTransaction(PolicyFactory::instance()->createTransaction(this, TR_CONFIG), handler)
{
    if(prepareds.empty() && search_pathes.empty() && init_queries.empty()) {
        ERROR("either prepared list, search path, init_queries are empty. nothing to do");
        return;
    }

    QueryChain* q = 0;

    if(!search_pathes.empty()) {
        string query("SET search_path TO ");
        for(auto& path : search_pathes) {
            query += path + ",";
        }
        query.pop_back();

        q = new QueryChain(new QueryParams(query, false, false));
    }

    if(!prepareds.empty()) {
        auto first = prepareds.begin();
        IPGQuery* firstq = new Prepared(first->first, first->second.query, first->second.oids);
        if(!q)
            q = new QueryChain(firstq);
        else
            q->addQuery(firstq);
        for(auto it = ++first; it != prepareds.end(); it++) {
            q->addQuery(new Prepared(it->first, it->second.query, it->second.oids));
        }
    }

    if(!init_queries.empty()) {
        auto it = init_queries.begin();
        IPGQuery* firstq = it->get();
        if(!q)
            q = new QueryChain(firstq->clone());
        else
            q->addQuery(firstq->clone());

        for(++it; it != init_queries.end(); ++it) {
            q->addQuery(it->get()->clone());
        }
    }

    exec(q);
}

ConfigTransaction::ConfigTransaction(const ConfigTransaction& trans)
: IPGTransaction(PolicyFactory::instance()->createTransaction(this, TR_CONFIG), trans.handler)
{
    if(trans.tr_impl->query)
        tr_impl->query = trans.tr_impl->query->clone();
}

template class DbTransaction<PGTransactionData::read_committed, PGTransactionData::write_policy::read_write>;
template class DbTransaction<PGTransactionData::read_committed, PGTransactionData::write_policy::read_only>;
template class DbTransaction<PGTransactionData::repeatable_read, PGTransactionData::write_policy::read_write>;
template class DbTransaction<PGTransactionData::repeatable_read, PGTransactionData::write_policy::read_only>;
template class DbTransaction<PGTransactionData::serializable, PGTransactionData::write_policy::read_write>;
template class DbTransaction<PGTransactionData::serializable, PGTransactionData::write_policy::read_only>;
template<> const char* DbTransaction<PGTransactionData::read_committed, PGTransactionData::write_policy::read_write>::begin_cmd  ="BEGIN";
template<> const char* DbTransaction<PGTransactionData::read_committed, PGTransactionData::write_policy::read_only>::begin_cmd   ="BEGIN READ ONLY";
template<> const char* DbTransaction<PGTransactionData::repeatable_read, PGTransactionData::write_policy::read_write>::begin_cmd ="BEGIN ISOLATION LEVEL REPEATABLE READ";
template<> const char* DbTransaction<PGTransactionData::repeatable_read, PGTransactionData::write_policy::read_only>::begin_cmd  ="BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY";
template<> const char* DbTransaction<PGTransactionData::serializable, PGTransactionData::write_policy::read_write>::begin_cmd    ="BEGIN ISOLATION LEVEL SERIALIZABLE";
template<> const char* DbTransaction<PGTransactionData::serializable, PGTransactionData::write_policy::read_only>::begin_cmd     ="BEGIN ISOLATION LEVEL SERIALIZABLE READ ONLY";

IPGTransaction* createDbTransaction(ITransactionHandler* handler, PGTransactionData::isolation_level il, PGTransactionData::write_policy wp)
{
    if(il == PGTransactionData::read_committed && wp == PGTransactionData::write_policy::read_write)
        return new DbTransaction<PGTransactionData::read_committed, PGTransactionData::write_policy::read_write>(handler);
    else if (il ==PGTransactionData::read_committed && wp == PGTransactionData::write_policy::read_only)
        return new DbTransaction<PGTransactionData::read_committed, PGTransactionData::write_policy::read_only>(handler);
    else if(il == PGTransactionData::repeatable_read && wp == PGTransactionData::write_policy::read_write)
        return new DbTransaction<PGTransactionData::repeatable_read, PGTransactionData::write_policy::read_write>(handler);
    else if(il == PGTransactionData::repeatable_read && wp == PGTransactionData::write_policy::read_only)
        return new DbTransaction<PGTransactionData::repeatable_read, PGTransactionData::write_policy::read_only>(handler);
    else if(il == PGTransactionData::serializable && wp == PGTransactionData::write_policy::read_write)
        return new DbTransaction<PGTransactionData::serializable, PGTransactionData::write_policy::read_write>(handler);
    else if(il == PGTransactionData::serializable && wp == PGTransactionData::write_policy::read_only)
        return new DbTransaction<PGTransactionData::serializable, PGTransactionData::write_policy::read_only>(handler);
    return 0;
}

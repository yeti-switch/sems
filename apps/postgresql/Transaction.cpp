#include "Transaction.h"
#include "Connection.h"
#include "pqtypes-int.h"
#include <log.h>
#include <netinet/in.h>
#include <jsonArg.h>

#define MAX_BUF_SIZE 256

void ITransaction::reset(IPGConnection* conn_)
{
    conn = conn_;
    query->reset(conn);
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
    if(tr_impl->query && tr_impl->check_trans()) {
        if(tr_impl->status == PQTRANS_ACTIVE) {
            tr_impl->fetch_result();
            if(is_finished()) {
                status = FINISH;
                handler->onFinish(this, tr_impl->result);
            } else {
                check();
            }
        } else if(tr_impl->status == PQTRANS_IDLE ||
                 tr_impl->status == PQTRANS_INTRANS) {
            int ret = 0;
            // 0 - run transaction request, do not run main query
            // 1 - transaction request is finished, run main query
            // -1 - error
            ret = begin();
            if(ret < 0) handler->onPQError(this, tr_impl->query->get_last_error());
            // 0 - main query finished, run end transaction request
            // 1 - main query sended, do not run end transaction request
            // -1 - error
            if(ret) ret = execute();
            else if(ret < 0) handler->onPQError(this, tr_impl->query->get_last_error());
            else return;
            if(!ret) ret = end();
            if(ret < 0) handler->onPQError(this, tr_impl->query->get_last_error());
        } else if(tr_impl->status == PQTRANS_INERROR) {
            status = ERROR;
            int ret = rollback();
            if(ret < 0) handler->onPQError(this, tr_impl->query->get_last_error());
        } else {
            ERROR("unknown state of database transaction");
        }
    }
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
        tr_impl->conn->cur_transition = 0;
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
            char* value = PQgetvalue(res, i, j);
            row.push(field_names[j], get_result(field_types[j], field_format[j], value));
        }
        if(single) parent->handler->onTuple(parent, row);
        result.push(row);
    }
}

void PGTransaction::fetch_result()
{
    if(!conn) {
        ERROR("absent connection");
        return;
    }

    PGresult* res;
    while((res=PQgetResult((PGconn*)conn->get()))) {
        bool single = false;
        ExecStatusType st = ExecStatusType::PGRES_COMMAND_OK;
        switch ((int)(st = PQresultStatus(res))) {
        case PGRES_EMPTY_QUERY:
        case PGRES_BAD_RESPONSE:
        case PGRES_NONFATAL_ERROR:
        case PGRES_FATAL_ERROR:
            parent->handler->onError(parent, PQresultErrorMessage(res));
            break;
        case PGRES_SINGLE_TUPLE: 
            single = true;
        case PGRES_TUPLES_OK:
            make_result(res, single);
            break;
        }

        PQclear(res);
    }

}

MockTransaction::MockTransaction(IPGTransaction* h, TransactionType t, TestServer* server_)
: ITransaction(h, t), server(server_), last_query(0)
{
    status = PQTRANS_IDLE;
}

MockTransaction::~MockTransaction() {}

bool MockTransaction::check_trans()
{
    if(status == PQTRANS_IDLE &&
       query->get_current_query()->is_finished() &&
       query->get_current_query() != last_query) {
            if(server->isError(query->get_query()))
                parent->handler->onError(parent, "mock error");
            status = PQTRANS_ACTIVE;
            last_query = query->get_current_query();
    } 
    return true;
}

void MockTransaction::fetch_result()
{
    status = PQTRANS_IDLE;
    AmArg res = server->getResponse(query->get_query());
    if(!isArgUndef(res))
        result.push(res);
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
        if(parent->get_state() == IPGTransaction::BODY && server->isError(query->get_query())) {
            status = PQTRANS_INERROR;
            parent->handler->onError(parent, "mock error");
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
, il(isolation), wp(rw) {
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
        IQuery* begin_q = PolicyFactory::instance()->createQuery(begin_cmd, false);
        begin_q->reset(get_conn());
        int ret = begin_q->exec();
        delete begin_q;
        state = BODY;
        return ret ? 0 : -1;
    }
    return 1;
}

template<PGTransactionData::isolation_level isolation, PGTransactionData::write_policy rw>
int DbTransaction<isolation, rw>::execute()
{
    if(!tr_impl->query->is_finished())
        return IPGTransaction::execute();
    else
        return 0;
}

template<PGTransactionData::isolation_level isolation, PGTransactionData::write_policy rw>
int DbTransaction<isolation, rw>::rollback()
{
    if(!get_conn()) {
        ERROR("absent connection");
        return -1;
    }
    if(state == BODY) {
        IQuery* end_q = PolicyFactory::instance()->createQuery("ROLLBACK", false);
        end_q->reset(get_conn());
        int ret = end_q->exec();
        delete end_q;
        state = END;
        if(ret) tr_impl->query->set_finished();
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
        IQuery* end_q = PolicyFactory::instance()->createQuery("END", false);
        end_q->reset(get_conn());
        int ret = end_q->exec();
        delete end_q;
        state = END;
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
    QueryParams* qexec = new QueryParams(prepared.stmt, prepared.qdata.single, true);
    vector<QueryParam> qparams = getParams(prepared.params);
    vector<unsigned int> oids;
    for(auto& param : qparams) {
        oids.push_back(param.get_oid());
        qexec->addParam(param);
    }
    QueryChain* query = new QueryChain(new Prepared(prepared.stmt, prepared.qdata.query, oids));
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
                                     ITransactionHandler* handler)
: IPGTransaction(PolicyFactory::instance()->createTransaction(this, TR_CONFIG), handler)
{
    if(prepareds.empty() && search_pathes.empty()) {
        ERROR("prepared list and search path are empty");
        return;
    }

    QueryChain* q = 0;
    if(!search_pathes.empty()) {
        string query("SET search_path TO ");
        for(auto& path : search_pathes) {
            query += path + ",";
        }
        query.pop_back();

        q = new QueryChain(new Query(query, false));
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

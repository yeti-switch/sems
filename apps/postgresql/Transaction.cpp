#include "Transaction.h"
#include "Connection.h"
#include <log.h>
#include <netinet/in.h>
#include <jsonArg.h>
#include <stdarg.h>
#include <AmUtils.h>

#define MAX_BUF_SIZE 256

char pg_log_buf[BUFSIZ];

int IPGTransaction::execute()
{
     if(tr_impl->query->exec() < 0)
         return -1;
     handler->onSend(this);
     return is_pipeline() ? (tr_impl->query->is_finished() ? 0 : 2) : 1;
}

void ITransaction::reset(IPGConnection* conn_)
{
    conn = conn_;
    synced = false;
    sync_sent = false;
    pipeline_aborted = false;
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

int IPGTransaction::check()
{
    int ret;
    int connection_is_busy = 0;
    bool next = false;

    do {
        TRANS_LOG(this, "IPGTransaction::check() in do while(%u)", next);

        if(!tr_impl->query) {
            ERROR("no query for transaction");
            break;
        }

        if(!tr_impl->check_trans()) {
            //no connection or connection is busy
            break;
        }

        /* FIXME: is it possible to has
         * status == FINISH and tr_impl->status == PQTRANS_INERROR */
        if(status == FINISH) {
            if(tr_impl->status == PQTRANS_INERROR) {
                ERROR("logical error. tr_impl->status:PQTRANS_INERROR for status:FINISH");
            }

            //transaction is finished
            break;
        }

        next = false;
        switch(tr_impl->status) {

        case PQTRANS_ACTIVE:
            connection_is_busy = tr_impl->fetch_result();
            if(is_finished()) {
                status = FINISH;
                handler->onFinish(this, tr_impl->result);
                TRANS_LOG(this, "transaction finished get %u results", get_query(true)->get_result_got());
                return connection_is_busy;
            }
            next = true;
            break;

        case PQTRANS_IDLE:
        case PQTRANS_INTRANS:
            TRANS_LOG(this, "status idle - send query");
            next = is_pipeline();

            //BEGIN request

            //  0 - run transaction request, do not run main query
            //  1 - transaction request is finished, run main query
            // -1 - error
            ret = begin();
            if(ret < 0) {
                ERROR("begin(): %d. query: %s, last_error:%s",
                    ret, tr_impl->query->get_query().data(),
                    tr_impl->query->get_last_error());

                handler->onPQError(this, tr_impl->query->get_last_error());
                return 0;
            }

            //FIXME: ensures old code behavior but looks strange
            if(0==ret) return 0;

            //query
            if(1==ret) {
                do {
                    //  0 - main query finished, run end transaction request
                    //  1 - main query sent, do not run end transaction request
                    //  2 - main query sending in pipeline mode
                    // -1 - error
                    ret = execute();
                    if(ret < 0) {
                        ERROR("execute(): %d. query: %s, last_error:%s",
                            ret, tr_impl->query->get_query().data(),
                            tr_impl->query->get_last_error());

                        handler->onPQError(this, tr_impl->query->get_last_error());
                        return 0;
                    }
                } while(ret > 1);
            }

            //END request
            if(0==ret) {
                //  0 - success
                // -1 - no connection or "END" query exec() error
                ret = end();
                if(ret < 0) {
                    ERROR("end(): %d. query: %s, last_error:%s",
                        ret, tr_impl->query->get_query().data(),
                        tr_impl->query->get_last_error());

                    handler->onPQError(this, tr_impl->query->get_last_error());
                    return 0;
                }
            }

            break;

        case PQTRANS_INERROR:
            TRANS_LOG(this, "status aborted - roolback");
            status = ERROR;
            ret = rollback();
            if(ret < 0) {
                ERROR("rollback(): %d. query: %s, last_error:%s",
                    ret, tr_impl->query->get_query().data(),
                    tr_impl->query->get_last_error());

                handler->onPQError(this, tr_impl->query->get_last_error());
                return 0;
            }
            if(tr_impl->conn->getPipeStatus() == PQ_PIPELINE_ON)
                tr_impl->conn->syncPipeline();
            break;
        default:
            ERROR("unexpected tr_impl->status: %d", tr_impl->status);
        } //switch(tr_impl->status)
    } while(next);

    return connection_is_busy;
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

IPGQuery * IPGTransaction::get_current_query(bool parent)
{
    if(!tr_impl->query) return 0;
    if(parent) return tr_impl->query;
    if(!is_pipeline()) return tr_impl->query->get_current_query();

    QueryChain* chain = dynamic_cast<QueryChain*>(tr_impl->query);
    if(!chain) return tr_impl->query;

    int num = chain->get_result_got();
    return chain->get_query(num);
}

string& IPGTransaction::get_transaction_log()
{
    static string result_log;
    for(auto& log : translog) {
        int sz = strftime(pg_log_buf, 26, "%b %d %T",&log.time);
        result_log.append(pg_log_buf, sz);
        sz = snprintf(pg_log_buf, sizeof(pg_log_buf), "[%s:%d] %s\n", log.file.c_str(), log.line, log.data.c_str());
        result_log.append(pg_log_buf, sz);
    }
    return result_log;
}

bool IPGTransaction::saveLog(const char* path)
{
    if(trans_log_written) return true;

    string dirPath = path;
    if(dirPath.empty()) return false;
    auto dirPathes = explode(dirPath, "/", true);

    std::string dir;
    for(auto &dirName : dirPathes) {
        dir += "/";
        dir += dirName;
        if(access(dir.c_str(), 0) != 0) {
            mkdir(dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        }
    }

    string& result_log = get_transaction_log();
    struct timeval tv;
    struct tm t;

    gettimeofday(&tv,NULL);
    localtime_r(&tv.tv_sec,&t);

    string file_path;
    strftime(pg_log_buf, 26, "%d-%b-%T",&t);
    file_path.append(pg_log_buf);
    snprintf(pg_log_buf, PATH_MAX, "%s/%d_%s.log", path, get_conn()->getSocket(), file_path.c_str());
    file_path = pg_log_buf;

    FILE* f = fopen(file_path.c_str(), "wb");
    if(!f) return false;

    fwrite(result_log.c_str(), result_log.size(), 1, f);
    fclose(f);

    trans_log_written = true;

    return true;
}

PGTransaction::PGTransaction(IPGTransaction* h, TransactionType t)
: ITransaction(h, t){}

PGTransaction::~PGTransaction(){}

bool PGTransaction::check_trans()
{
    if(!conn) {
        ERROR("absent connection");
        return false;
    }

    if(conn->getPipeStatus() == PQ_PIPELINE_ON && query->is_finished() && !sync_sent) {
        TRANS_LOG(parent, "send Sync");
        conn->syncPipeline();
        sync_sent = true;
    }
    status = PQtransactionStatus(*conn);
    return !PQisBusy(*conn);
}

bool PGTransaction::cancel_trans()
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
    TRANS_LOG(parent, "result: %s", AmArg::print(result).c_str());
}

int PGTransaction::fetch_result()
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

            PQclear(res);
            res = PQgetResult(*conn);
            if(!res) query->put_result();
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
    Query* single = dynamic_cast<Query*>(query);
    QueryChain* chain = dynamic_cast<QueryChain*>(query);
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
        return true;
    }
        
    if((status == PQTRANS_IDLE &&
       query->is_finished()) ||
        status == PQTRANS_ACTIVE) {
        status = PQTRANS_ACTIVE;    
        return !server->checkTail(query_);
    }

    return true;
}

int MockTransaction::fetch_result()
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
        return 0;
    }

    server->clearTail(query_);
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

    return 0;
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
        TRANS_LOG(this, "exec: %s", begin_cmd);
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
        else if(ret == 1 && is_pipeline()) return 2;
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
        tr_impl->pipeline_aborted = false;
        if(ret) tr_impl->query->set_finished();
        TRANS_LOG(this, "exec: ROLLBACK");
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
IPGQuery * DbTransaction<isolation, rw>::get_current_query(bool parent)
{
    if(!tr_impl->query) return 0;
    if(parent) return tr_impl->query;
    if(!is_pipeline()) return tr_impl->query->get_current_query();

    QueryChain* chain = dynamic_cast<QueryChain*>(tr_impl->query);
    if(!chain) return tr_impl->query;

    uint32_t num = chain->get_result_got();
    if(num <= 1) return chain->get_query(0);
    else if(num - 1 >= chain->get_size()) return chain->get_current_query();
    return chain->get_query(num - 1);
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
        TRANS_LOG(this, "exec: END");
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

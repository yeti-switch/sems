#include "Transaction.h"

#include "../PostgreSQL.h"
#include "../conn/Connection.h"
#include "../query/QueryChain.h"

#include <log.h>
#include <jsonArg.h>
#include <AmUtils.h>

#include <stdarg.h>
#include <netinet/in.h>

#define MAX_BUF_SIZE 256

char pg_log_buf[BUFSIZ];

Transaction::Transaction(TransactionImpl* impl, ITransactionHandler* handler)
    : handler(handler), tr_impl(impl)
    , status(ACTIVE), state(BEGIN)
#ifdef TRANS_LOG_ENABLE
    , counter(0)
{
    string dirPath = PostgreSQL::instance()->getConnectionLogPath();
    if(dirPath.empty()) dirPath = ".";
    auto dirPathes = explode(dirPath, "/", true);

    std::string dir;
    for(auto &dirName : dirPathes) {
        dir += "/";
        dir += dirName;
        if(access(dir.c_str(), 0) != 0) {
            mkdir(dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        }
    }

    struct timeval tv;
    struct tm t;
    gettimeofday(&tv,NULL);
    localtime_r(&tv.tv_sec,&t);

    strftime(pg_log_buf, 26, "%d-%b-%T",&t);
    file_path.append(pg_log_buf);
    snprintf(pg_log_buf, PATH_MAX, "%s/%p_%s.log", dirPath.c_str(), this, file_path.c_str());
    file_path = pg_log_buf;
#else
{
#endif
}

int Transaction::begin() {
    state = BODY;
    return 1;
}

int Transaction::end() {
    state = END;
    return tr_impl->is_pipeline() ? 2 : 1;
}

int Transaction::rollback() {
    state = END;
    return 1;
}

int Transaction::execute()
{
     if(tr_impl->query->exec() < 0)
         return -1;
     handler->onSend(this);
     return is_pipeline() ? (tr_impl->query->is_finished() ? 0 : 2) : 1;
}

bool Transaction::cancel()
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

int Transaction::check()
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
                TRANS_LOG(this, "transaction finished get %u results", get_query(true)->get_result_got());
                status = FINISH;
                handler->onFinish(this, tr_impl->result);
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
                //  1 - success
                //  2 - success in pipeline mode
                //  0 - incorrect state, ignore
                // -1 - no connection or "END" query exec() error
                ret = end();
                if(ret < 0) {
                    ERROR("end(): %d. query: %s, last_error:%s",
                        ret, tr_impl->query->get_query().data(),
                        tr_impl->query->get_last_error());

                    handler->onPQError(this, tr_impl->query->get_last_error());
                    return 0;
                }
                if(ret == 2) {
                    TRANS_LOG(this, "send Sync");
                    tr_impl->sync_pipeline();
                }
            }

            break;

        case PQTRANS_INERROR:
            status = ERROR;
            TRANS_LOG(this, "status aborted - roolback");
            ret = rollback();
            if(ret < 0) {
                ERROR("rollback(): %d. query: %s, last_error:%s",
                    ret, tr_impl->query->get_query().data(),
                    tr_impl->query->get_last_error());

                handler->onPQError(this, tr_impl->query->get_last_error());
                return 0;
            }
            if(ret == 2) {
                TRANS_LOG(this, "send Sync");
                tr_impl->sync_pipeline();
            }
            break;
        default:
            ERROR("unexpected tr_impl->status: %d", tr_impl->status);
        } //switch(tr_impl->status)
    } while(next);

    return connection_is_busy;
}

bool Transaction::exec(IQuery* query)
{
    if(tr_impl->query) return false;

    tr_impl->query = query;
    return true;
}

void Transaction::reset(Connection *conn)
{
    status = ACTIVE;
    state = BEGIN;
    if(tr_impl->conn)
        tr_impl->conn->cur_transaction = 0;
    tr_impl->reset(conn);
}

bool Transaction::merge(Transaction* trans)
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

IQuery * Transaction::get_current_query(bool parent)
{
    if(!tr_impl->query) return 0;
    if(parent) return tr_impl->query;
    if(!is_pipeline()) return tr_impl->query->get_current_query();

    QueryChain* chain = dynamic_cast<QueryChain*>(tr_impl->query);
    if(!chain) return tr_impl->query;

    auto num = chain->get_result_got();
    if(num >= chain->get_size()) {
        if(num != chain->get_size()) {
            WARN("got result (%d) more than chain size (%d), return last query",
                num, chain->get_size());
        }
        num = chain->get_size() - 1;
    }
    return chain->get_query(num);
}

#ifdef TRANS_LOG_ENABLE
string Transaction::get_transaction_log()
{
    std::stringstream ss;
    std::time_t t;

    for(auto& log : translog) {
        t = std::chrono::system_clock::to_time_t(log.time);
        ss << std::put_time(std::localtime(&t), "%b %d %T\n");
        ss << "[" << log.file << ": " << log.line << "] " << log.data << std::endl;
    }

    return ss.str();
}

bool Transaction::saveLog()
{
    string result_log(get_transaction_log());

    FILE* f = fopen(file_path.c_str(), "wb");
    if(!f) return false;
    fwrite(result_log.c_str(), result_log.size(), 1, f);
    fclose(f);

    return true;
}

void Transaction::deleteLog()
{
    unlink(file_path.c_str());
}

#endif

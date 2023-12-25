#pragma once

#include <AmArg.h>
#include <ampi/PostgreSqlAPI.h>
#include "../PolicyFactory.h"

#include "TransactionImpl.h"
#include "ITransactionHandler.h"

#include <postgresql/libpq-fe.h>
#include <string>
#include <chrono>
#include <iomanip>

//uncomment to enable in-memory transaction logging
//#define TRANS_LOG_ENABLE
#ifdef TRANS_LOG_ENABLE
#define TRANS_LOG(trans, fmt, args...) \
    trans->add_log(FUNC_NAME, __FILE__, __LINE__, fmt, ##args);\
    if(trans->get_status() == Transaction::FINISH)\
        trans->deleteLog();\
    else if(trans->get_status() == Transaction::ERROR)\
        trans->saveLog();
#else
#define TRANS_LOG(trans, fmt, args...) ;
#endif

using std::string;

class Connection;
class Transaction;

extern char pg_log_buf[BUFSIZ];

class Transaction
{
  public:
    enum DbState {
        BEGIN = 0,
        BODY,
        END
    };

    enum Status
    {
        ACTIVE = 0,
        CANCELING,
        ERROR,
        FINISH
    };

    ITransactionHandler* handler;

  protected:
    TransactionImpl* tr_impl;
    Status status;
    DbState state;

    virtual int begin();
    virtual int end();
    virtual int rollback();
    virtual int execute();
    virtual bool is_finished() { return is_pipeline() ? tr_impl->is_synced() : tr_impl->query->is_finished(); }
    virtual bool is_equal(Transaction* trans) { return trans->get_type() == get_type(); }
    virtual Transaction* make_clone() = 0;
    virtual PGTransactionData policy() = 0;
    virtual IQuery* get_current_query(bool parent);

    Transaction(TransactionImpl* impl, ITransactionHandler* handler);

  public:
    virtual ~Transaction() { delete tr_impl; }

    int check();
    bool exec(IQuery* query);
    bool cancel();
    void reset(Connection* conn);
    bool merge(Transaction* trans);
    Transaction* clone() { return make_clone(); }
    IQuery* get_query(bool parent = false) { return get_current_query(parent); }
    PGTransactionData get_policy() { return policy(); }
    bool is_pipeline() { return tr_impl->is_pipeline(); }

    const AmArg& get_result() { return tr_impl->result; }
    Status get_status() { return status; }
    DbState get_state() { return state; }
    Connection* get_conn() { return tr_impl->conn; }
    TransactionType get_type() { return tr_impl->type; }
    uint32_t get_size() { return tr_impl->query->get_size(); }

    struct TransLog
    {
        std::chrono::system_clock::time_point time;
        string func;
        string file;
        int line;
        string data;
        TransLog(const char* file, int line)
          : time(std::chrono::system_clock::now()),
            file(file),
            line(line)
        {}
    };
#ifdef TRANS_LOG_ENABLE
    vector<TransLog> translog;
    string file_path;
    int counter;
    template<class... Types> void add_log(const char* func, const char* file, int line,
                                          const char* format, Types... args);
    string get_transaction_log();
    bool saveLog();
    void deleteLog();
#endif
};

#ifdef TRANS_LOG_ENABLE
template<class... Types> void Transaction::add_log(const char* func, const char* file, int line,
                                      const char* format, Types... args)
{
    translog.emplace_back(file,line);
    TransLog& tlog = translog.back();

    if constexpr (sizeof...(args) > 0) {
        snprintf(pg_log_buf, sizeof(pg_log_buf), format, args...);
        tlog.data = pg_log_buf;
    } else {
        tlog.data = format;
    }

    // counter++;
    // if(counter > 10) {
    //     saveLog();
    //     counter = 0;
    // }
}
#endif

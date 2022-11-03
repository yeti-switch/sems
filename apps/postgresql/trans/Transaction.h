#pragma once

#include <AmArg.h>
#include <ampi/PostgreSqlAPI.h>
#include "../PolicyFactory.h"
#include "../query/Query.h"

#include "TransactionImpl.h"
#include "ITransactionHandler.h"

#include <postgresql/libpq-fe.h>
#include <string>
#include <chrono>

#define TRANS_LOG(trans, fmt, args...) trans->add_log(FUNC_NAME, __FILE__, __LINE__, fmt, ##args)

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

    virtual int begin() { state = BODY; return 1; }
    virtual int end() { state = END; return 1; }
    virtual int rollback() { state = END; return 1; }
    virtual int execute();
    virtual bool is_finished() { return is_pipeline() ? tr_impl->is_synced() : tr_impl->query->is_finished(); }
    virtual bool is_equal(Transaction* trans) { return trans->get_type() == get_type(); }
    virtual Transaction* make_clone() = 0;
    virtual PGTransactionData policy() = 0;
    virtual IQuery* get_current_query(bool parent);

    Transaction(TransactionImpl* impl, ITransactionHandler* handler)
        : handler(handler), tr_impl(impl)
        , status(ACTIVE), state(BEGIN)
        , trans_log_written(false)
    {}

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
    bool trans_log_written;
    vector<TransLog> translog;
    template<class... Types> void add_log(const char* func, const char* file, int line,
                                          const char* format, Types... args);
    string get_transaction_log();
    bool saveLog(const char* path);
};

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
}

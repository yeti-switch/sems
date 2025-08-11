#pragma once

#include <AmArg.h>

#include <cstdint>
#include <string>
#include <vector>
#include <map>
using std::map;
using std::string;
using std::vector;

#include "unit_tests/TestServer.h"

class Connection;
struct IConnectionHandler;
struct ITransactionHandler;
class Transaction;
class TransactionImpl;
struct IQuery;
class IQueryImpl;

enum TransactionType { TR_NON, TR_POLICY, TR_PREPARED, TR_CONFIG };

class TestServer;

class PolicyFactory {
    friend PolicyFactory *makePolicyFactory(bool, TestServer *);
    static PolicyFactory *instance_;

  protected:
    PolicyFactory() {}
    virtual ~PolicyFactory() {}

  public:
    static PolicyFactory *instance() { return instance_; }
    static void           dispose();

    virtual Connection      *createConnection(const string &conn_info, const string &conn_log_info,
                                              IConnectionHandler *handler)                = 0;
    virtual TransactionImpl *createTransaction(Transaction *parent, TransactionType type) = 0;

    virtual IQueryImpl *createSimpleQuery(const string &cmd, bool singleMode)                                 = 0;
    virtual IQueryImpl *createQueryParam(const string &cmd, bool singleMode, IQuery *parent)                  = 0;
    virtual IQueryImpl *createPrepared(const string &stmt, const string &cmd, const vector<uint32_t> &params) = 0;
    virtual IQueryImpl *createQueryPrepared(const std::string &cmd, bool singleMode, IQuery *parent)          = 0;
};

class TestPolicy : public PolicyFactory {
    TestServer *server;

  public:
    TestPolicy(TestServer *server_)
        : server(server_)
    {
    }
    ~TestPolicy() {}

    Connection      *createConnection(const std::string &conn_info, const string &conn_log_info,
                                      IConnectionHandler *handler) override;
    TransactionImpl *createTransaction(Transaction *handler, TransactionType type) override;
    IQueryImpl      *createSimpleQuery(const std::string &cmd, bool singleMode) override;
    IQueryImpl      *createQueryParam(const string &cmd, bool singleMode, IQuery *parent) override;
    IQueryImpl      *createPrepared(const string &stmt, const string &cmd, const vector<uint32_t> &params) override;
    IQueryImpl      *createQueryPrepared(const std::string &cmd, bool singleMode, IQuery *parent) override;
};

class PGPolicy : public PolicyFactory {
  public:
    PGPolicy() {}
    ~PGPolicy() {}

    Connection      *createConnection(const std::string &conn_info, const std::string &conn_log_info,
                                      IConnectionHandler *handler) override;
    TransactionImpl *createTransaction(Transaction *parent, TransactionType type) override;
    IQueryImpl      *createSimpleQuery(const std::string &cmd, bool singleMode) override;
    IQueryImpl      *createQueryParam(const string &cmd, bool singleMode, IQuery *parent) override;
    IQueryImpl      *createPrepared(const string &stmt, const string &cmd, const vector<uint32_t> &params) override;
    IQueryImpl      *createQueryPrepared(const std::string &cmd, bool singleMode, IQuery *parent) override;
};

PolicyFactory *makePolicyFactory(bool test, TestServer *server = 0);
void           freePolicyFactory();

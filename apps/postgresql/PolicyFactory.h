#ifndef POLICY_FACTORY_H
#define POLICY_FACTORY_H

#include <AmArg.h>

#include <string>
#include <vector>
#include <map>
using std::string;
using std::map;
using std::vector;

class IPGConnection;
struct IConnectionHandler;
struct ITransactionHandler;
class IPGTransaction;
class ITransaction;
class IQuery;
struct IPGQuery;

enum TransactionType {
    TR_NON,
    TR_POLICY,
    TR_PREPARED,
    TR_CONFIG
};

class TestServer;

class PolicyFactory
{
    friend PolicyFactory* makePolicyFactory(bool, TestServer*);
    static PolicyFactory* instance_;
protected:
    PolicyFactory(){}
    virtual ~PolicyFactory(){}
public:
    static PolicyFactory* instance() { return instance_; }
    static void dispose();

    virtual IPGConnection* createConnection(const string& conn_info, IConnectionHandler* handler) = 0;
    virtual ITransaction*  createTransaction(IPGTransaction* parent,
                                             TransactionType type) = 0;
    virtual IQuery*        createQuery(const string& cmd, bool singleMode) = 0;
    virtual IQuery*        createQueryParam(const string& cmd,
                                            bool singleMode, IPGQuery* parent) = 0;
    virtual IQuery *       createPrepared(const string& stmt,
                                           const string& cmd, const vector<uint32_t>& params) = 0;
    virtual IQuery *       createQueryPrepared(const std::string& cmd,
                                               bool singleMode, IPGQuery* parent) = 0;
};

class TestServer
{
    map<string, AmArg> responses;
    map<string, bool> errors;
public:
    TestServer(){}

    void addResponse(const string& query, const AmArg& response) {
        responses.emplace(query, response);
    }

    void addError(const string& query, bool erase) {
        errors.emplace(query, erase);
    }

    bool isError(const string& query) {
        for(auto it = errors.begin();
            it != errors.end(); it++) {
            if(it->first == query) {
                if(it->second) errors.erase(it);
                return true;
            }
        }
        return false;
    }

    AmArg& getResponse(const string& query) {
        return responses[query];
    }

    void clear() {
        responses.clear();
        errors.clear();
    }
};

class TestPolicy : public PolicyFactory
{
    TestServer* server;
public:
    TestPolicy(TestServer* server_) : server(server_){}
    ~TestPolicy(){}
    IPGConnection * createConnection(const std::string & conn_info, IConnectionHandler * handler) override;
    ITransaction * createTransaction(IPGTransaction* handler,
                                     TransactionType type) override;
    IQuery * createQuery(const std::string & cmd, bool singleMode) override;
    IQuery * createQueryParam(const string& cmd, bool singleMode, IPGQuery* parent) override;
    IQuery * createPrepared(const string& stmt,
                            const string& cmd, const vector<uint32_t>& params) override;
    IQuery * createQueryPrepared(const std::string& cmd,
                                 bool singleMode, IPGQuery* parent) override;
};

class PGPolicy : public PolicyFactory
{
public:
    PGPolicy(){}
    ~PGPolicy(){}
    IPGConnection * createConnection(const std::string & conn_info, IConnectionHandler * handler) override;
    ITransaction * createTransaction(IPGTransaction* parent,
                                     TransactionType type) override;
    IQuery * createQuery(const std::string & cmd, bool singleMode) override;
    IQuery * createQueryParam(const string& cmd, bool singleMode, IPGQuery* parent) override;
    IQuery * createPrepared(const string& stmt,
                            const string& cmd, const vector<uint32_t>& params) override;
    IQuery * createQueryPrepared(const std::string& cmd,
                                 bool singleMode, IPGQuery* parent) override;
};

PolicyFactory* makePolicyFactory(bool test, TestServer* server = 0);

#endif/*POLICY_FACTORY_H*/

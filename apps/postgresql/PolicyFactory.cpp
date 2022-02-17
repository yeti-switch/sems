#include "PolicyFactory.h"
#include "Connection.h"
#include "Transaction.h"
#include "Query.h"

PolicyFactory* PolicyFactory::instance_ = 0;

void PolicyFactory::dispose()
{
    if(PolicyFactory::instance_) {
        delete PolicyFactory::instance_;
        PolicyFactory::instance_ = 0;
    }
}

IPGConnection * PGPolicy::createConnection(const string& conn_info, IConnectionHandler* handler)
{
    return new PGConnection(conn_info, handler);
}

IPGConnection * TestPolicy::createConnection(const string&, IConnectionHandler* handler)
{
    return new MockConnection(handler);
}

ITransaction * PGPolicy::createTransaction(IPGTransaction* parent, TransactionType type)
{
    return new PGTransaction(parent, type);
}

ITransaction * TestPolicy::createTransaction(IPGTransaction* parent, TransactionType type)
{
    if(type == TR_POLICY) 
        return new DbMockTransaction(parent, server);
    return new MockTransaction(parent, type, server);
}

IQuery * PGPolicy::createQuery(const string& cmd, bool singleMode)
{
    return new PGQuery(cmd, singleMode);
}

IQuery * TestPolicy::createQuery(const string& cmd, bool singleMode)
{
    return new MockQuery(cmd, singleMode);
}

IQuery * PGPolicy::createQueryParam(const std::string& cmd, bool singleMode, IPGQuery* parent)
{
    return new PGQueryParam(cmd, singleMode, (QueryParams*)parent);
}

IQuery * TestPolicy::createQueryParam(const std::string& cmd, bool singleMode, IPGQuery* parent)
{
    return new MockQuery(cmd, singleMode);
}

IQuery * PGPolicy::createPrepared(const std::string& stmt,
                                  const std::string& cmd, const vector<uint32_t>& params)
{
    return new PGPrepared(stmt, cmd, params);
}

IQuery * TestPolicy::createPrepared(const std::string& stmt,
                                    const std::string& cmd, const vector<uint32_t>& params)
{
    return new MockQuery(cmd, false);
}

IQuery * PGPolicy::createQueryPrepared(const std::string& stmt, bool singleMode, IPGQuery* parent)
{
    return new PGQueryPrepared(stmt, singleMode, (QueryParams*)parent);
}

IQuery * TestPolicy::createQueryPrepared(const std::string& cmd, bool singleMode, IPGQuery* parent)
{
    return new MockQuery(cmd, false);
}

PolicyFactory * makePolicyFactory(bool test, TestServer* server)
{
    if(PolicyFactory::instance_)
        return PolicyFactory::instance();

    if(test)
        PolicyFactory::instance_ = new TestPolicy(server);
    else
        PolicyFactory::instance_ = new PGPolicy;
    return PolicyFactory::instance();
}

#include "PolicyFactory.h"

#include "conn/Connection.h"
#include "conn/PGConnection.h"
#include "conn/MockConnection.h"

#include "trans/Transaction.h"
#include "trans/PGTransactionImpl.h"
#include "trans/DbMockTransactionImpl.h"

#include "query/SimpleQueryImpl.h"
#include "query/MockQueryImpl.h"
#include "query/PrepareQueryImpl.h"
#include "query/ParameterizedQueryImpl.h"
#include "query/ExecutePreparedQueryImpl.h"

PolicyFactory *PolicyFactory::instance_ = 0;

void PolicyFactory::dispose()
{
    if (PolicyFactory::instance_) {
        delete PolicyFactory::instance_;
        PolicyFactory::instance_ = 0;
    }
}

Connection *PGPolicy::createConnection(const string &conn_info, const std::string &conn_log_info,
                                       IConnectionHandler *handler)
{
    return new PGConnection(conn_info, conn_log_info, handler);
}

Connection *TestPolicy::createConnection(const string &, const string &, IConnectionHandler *handler)
{
    return new MockConnection(handler);
}

TransactionImpl *PGPolicy::createTransaction(Transaction *parent, TransactionType type)
{
    return new PGTransactionImpl(parent, type);
}

TransactionImpl *TestPolicy::createTransaction(Transaction *parent, TransactionType type)
{
    if (type == TR_POLICY)
        return new DbMockTransactionImpl(parent, server);
    return new MockTransactionImpl(parent, type, server);
}

IQueryImpl *PGPolicy::createSimpleQuery(const string &cmd, bool singleMode)
{
    return new SimpleQueryImpl(cmd, singleMode);
}

IQueryImpl *TestPolicy::createSimpleQuery(const string &cmd, bool singleMode)
{
    return new MockQueryImpl(cmd, singleMode);
}

IQueryImpl *PGPolicy::createQueryParam(const std::string &cmd, bool singleMode, IQuery *parent)
{
    return new ParameterizedQueryImpl(cmd, singleMode, (QueryParams *)parent);
}

IQueryImpl *TestPolicy::createQueryParam(const std::string &cmd, bool singleMode, IQuery *parent)
{
    return new MockQueryImpl(cmd, singleMode);
}

IQueryImpl *PGPolicy::createPrepared(const std::string &stmt, const std::string &cmd, const vector<uint32_t> &params)
{
    return new PrepareQueryImpl(stmt, cmd, params);
}

IQueryImpl *TestPolicy::createPrepared(const std::string &stmt, const std::string &cmd, const vector<uint32_t> &params)
{
    return new MockQueryImpl(cmd, false);
}

IQueryImpl *PGPolicy::createQueryPrepared(const std::string &stmt, bool singleMode, IQuery *parent)
{
    return new ExecutePreparedQueryImpl(stmt, singleMode, (QueryParams *)parent);
}

IQueryImpl *TestPolicy::createQueryPrepared(const std::string &cmd, bool singleMode, IQuery *parent)
{
    return new MockQueryImpl(cmd, false);
}

PolicyFactory *makePolicyFactory(bool test, TestServer *server)
{
    if (PolicyFactory::instance_)
        return PolicyFactory::instance_;

    if (test)
        PolicyFactory::instance_ = new TestPolicy(server);
    else
        PolicyFactory::instance_ = new PGPolicy;
    return PolicyFactory::instance();
}

void freePolicyFactory()
{
    PolicyFactory::dispose();
}

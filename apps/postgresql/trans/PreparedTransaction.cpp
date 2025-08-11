#include "PreparedTransaction.h"

#include "../query/QueryParams.h"
#include "../query/QueryChain.h"
#include "../query/QueryPrepare.h"

PreparedTransaction::PreparedTransaction(const std::string &stmt, const std::string &cmd, const vector<Oid> &oids,
                                         ITransactionHandler *handler)
    : Transaction(PolicyFactory::instance()->createTransaction(this, TR_PREPARED), handler)
{
    exec(new QueryPrepare(stmt, cmd, oids));
}

PreparedTransaction::PreparedTransaction(const map<string, PGPrepareData> &prepareds, ITransactionHandler *handler)
    : Transaction(PolicyFactory::instance()->createTransaction(this, TR_PREPARED), handler)
{
    if (prepareds.empty()) {
        ERROR("prepared list is empty");
        return;
    }
    auto        first = prepareds.begin();
    QueryChain *query = new QueryChain(new QueryPrepare(first->first, first->second.query, first->second.oids));
    for (auto it = ++first; it != prepareds.end(); it++) {
        query->addQuery(new QueryPrepare(it->first, it->second.query, it->second.oids));
    }
    exec(query);
}

PreparedTransaction::PreparedTransaction(const PGPrepareExec &prepared, ITransactionHandler *handler)
    : Transaction(PolicyFactory::instance()->createTransaction(this, TR_PREPARED), handler)
{
    QueryParams         *qexec   = new QueryParams(prepared.stmt, prepared.info.single, true);
    vector<QueryParam>   qparams = getParams(prepared.info.params);
    vector<unsigned int> oids;
    for (auto &param : qparams) {
        oids.push_back(param.get_oid());
        qexec->addParam(param);
    }
    QueryChain *query = new QueryChain(new QueryPrepare(prepared.stmt, prepared.info.query, oids));
    query->addQuery(qexec);
    exec(query);
}

PreparedTransaction::PreparedTransaction(const PreparedTransaction &trans)
    : Transaction(PolicyFactory::instance()->createTransaction(this, TR_PREPARED), trans.handler)
{
    if (trans.tr_impl->query)
        tr_impl->query = trans.tr_impl->query->clone();
}

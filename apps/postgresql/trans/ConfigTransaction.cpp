#include "ConfigTransaction.h"

#include "../query/QueryParams.h"
#include "../query/QueryChain.h"
#include "../query/QueryPrepare.h"

ConfigTransaction::ConfigTransaction(const map<std::string, PGPrepareData>& prepareds,
                                     const vector<std::string>& search_pathes,
                                     const vector< std::unique_ptr<IQuery> > &init_queries,
                                     ITransactionHandler* handler)
  : Transaction(PolicyFactory::instance()->createTransaction(this, TR_CONFIG), handler)
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
        auto firstq = new QueryPrepare(first->first, first->second.query, first->second.oids);
        if(!q)
            q = new QueryChain(firstq);
        else
            q->addQuery(firstq);
        for(auto it = ++first; it != prepareds.end(); it++) {
            q->addQuery(new QueryPrepare(it->first, it->second.query, it->second.oids));
        }
    }

    if(!init_queries.empty()) {
        auto it = init_queries.begin();
        auto firstq = it->get();
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
  : Transaction(PolicyFactory::instance()->createTransaction(this, TR_CONFIG), trans.handler)
{
    if(trans.tr_impl->query)
        tr_impl->query = trans.tr_impl->query->clone();
}

#include "Query.h"
#include "Connection.h"

int PGQuery::exec()
{
    if(!conn) {
        last_error = "absent connection";
        return -1;
    }
    bool ret = false;
    is_send = false;
    ret = is_send = PQsendQuery((PGconn*)conn->get(), query.c_str());
    if(!ret) last_error = PQerrorMessage((PGconn*)conn->get());
    if(is_send && single_mode) {
        ret = PQsetSingleRowMode((PGconn*)conn->get());
        if(!ret) last_error = PQerrorMessage((PGconn*)conn->get());
    }
    return ret ? 1 : -1;
}

QueryParams& QueryParams::addParam(const QueryParam& param)
{
    params.push_back(param);
    return *this;
}

void QueryParams::addParams(const vector<QueryParam>& params_)
{
    params = params_;
}

int PGQueryParam::exec()
{
    if(!conn) {
        last_error = "absent connection";
        return -1;
    }

    bool ret = false;
    is_send = false;
    vector<unsigned int> oids;
    vector<const char*> values;
    vector<int> lengths;
    vector<int> formats;
    for(auto& param : parent->params) {
        oids.push_back(param.get_oid());
        values.push_back(param.get_value());
        lengths.push_back(param.get_length());
        formats.push_back(param.is_binary_format());
    }
    ret = is_send = PQsendQueryParams((PGconn*)conn->get(), query.c_str(),
                                      parent->params.size(), oids.data(), values.data(),
                                      lengths.data(), formats.data(), 0);
    if(!ret) last_error = PQerrorMessage((PGconn*)conn->get());
    if(is_send && single_mode) {
        ret = PQsetSingleRowMode((PGconn*)conn->get());
        if(!ret) last_error = PQerrorMessage((PGconn*)conn->get());
    }
    return ret ? 1 : -1;
}

int PGPrepared::exec()
{
    if(!conn) {
        last_error = "absent connection";
        return -1;
    }

    bool ret = is_send = PQsendPrepare((PGconn*)conn->get(), stmt.c_str(), query.c_str(), oids.size(), oids.data());
    if(!ret) last_error = PQerrorMessage((PGconn*)conn->get());
    return ret ? 1 : -1;
}

int PGQueryPrepared::exec()
{
    if(!conn) {
        last_error = "absent connection";
        return -1;
    }

    bool ret = false;
    is_send = false;
    vector<const char*> values;
    vector<int> lengths;
    vector<int> formats;
    for(auto& param : parent->params) {
        values.push_back(param.get_value());
        lengths.push_back(param.get_length());
        formats.push_back(param.is_binary_format());
    }
    ret = is_send = PQsendQueryPrepared((PGconn*)conn->get(), query.c_str(),
                                      parent->params.size(), values.data(),
                                      lengths.data(), formats.data(), 0);
    if(!ret) last_error = PQerrorMessage((PGconn*)conn->get());
    if(is_send && single_mode) {
        ret = PQsetSingleRowMode((PGconn*)conn->get());
        if(!ret) last_error = PQerrorMessage((PGconn*)conn->get());
    }
    return ret ? 1 : -1;
}

int QueryChain::exec()
{
    if(current == childs.size()) return 0;
//     DBG("exec %zu: %s", current, childs[current]->get_query().c_str());
    int ret = childs[current]->exec();
    if(ret > 0) is_sended = true;
    if(ret > 0 && current + 1 != childs.size()) {
        current++;
        is_sended = false;
    }
    return ret;
}

IPGQuery * QueryChain::get_current_query()
{
    if(!current) return childs[current];
    else if(childs[current]->is_finished()) return childs[current];
    else return childs[current-1];
}

void QueryChain::addQuery(IPGQuery* q)
 {
    QueryChain* chain = dynamic_cast<QueryChain*>(q);
    if(!chain) {
        childs.push_back(q);
    } else {
        childs.insert(childs.end(), chain->childs.begin(), chain->childs.end());
        chain->childs.clear();
        delete chain;
    }
}

void QueryChain::removeQuery(IPGQuery* q)
 {
    for(auto it = childs.begin();
        it != childs.end(); it++) {
        if(*it == q) {
            childs.erase(it);
            break;
        }
    }
}

IPGQuery * QueryChain::clone()
{
    QueryChain* q = new QueryChain;
    for(auto& child : childs)
        q->addQuery(child->clone());
    return q;
}

void QueryChain::reset(IPGConnection* conn)
 {
    current = 0;
    is_sended = false;
    finished = false;
    for(auto& child : childs) child->reset(conn);
}

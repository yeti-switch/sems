#include "QueryChain.h"
#include "../conn/Connection.h"
#include "../trans/Transaction.h"

int QueryChain::exec()
{
    if (current == childs.size())
        return 0;
    TRANS_LOG(getConnection()->getCurrentTransaction(), "exec %zu: %s", current, childs[current]->get_query().c_str());
    int ret = childs[current]->exec();
    if (ret > 0)
        is_sent = true;
    if (ret > 0 && current + 1 != childs.size()) {
        current++;
        is_sent = false;
    }
    return ret;
}

IQuery *QueryChain::get_current_query()
{
    if (current >= get_size())
        return childs[childs.size() - 1]; // finished last query
    else if (!current)
        return childs[current]; // incomplete first query
    else if (childs[current]->is_finished())
        return childs[current]; // finished current query
    else
        return childs[current - 1]; // incomplete current query
}

void QueryChain::put_result()
{
    got_result++;
    TRANS_LOG(getConnection()->getCurrentTransaction(), "put result: %u", got_result);
}

void QueryChain::addQuery(IQuery *q)
{
    QueryChain *chain = dynamic_cast<QueryChain *>(q);
    if (!chain) {
        childs.push_back(q);
    } else {
        childs.insert(childs.end(), chain->childs.begin(), chain->childs.end());
        chain->childs.clear();
        delete chain;
    }
}

void QueryChain::removeQuery(IQuery *q)
{
    for (auto it = childs.begin(); it != childs.end(); it++) {
        if (*it == q) {
            childs.erase(it);
            break;
        }
    }
}

IQuery *QueryChain::clone()
{
    QueryChain *q = new QueryChain;
    for (auto &child : childs)
        q->addQuery(child->clone());
    return q;
}

void QueryChain::reset(Connection *conn)
{
    current    = 0;
    got_result = 0;
    is_sent    = false;
    finished   = false;
    for (auto &child : childs)
        child->reset(conn);
}

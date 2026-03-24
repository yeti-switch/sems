#include "QueryChain.h"
#include "../conn/Connection.h"
#include "../trans/Transaction.h"
#include <algorithm>

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
    size_t send_idx = (current < childs.size()) ? current : childs.size() - 1;
    size_t recv_idx = ((size_t)got_result < childs.size()) ? (size_t)got_result : childs.size() - 1;
    return childs[std::min(send_idx, recv_idx)];
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

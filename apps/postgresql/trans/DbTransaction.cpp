#include "DbTransaction.h"
#include "../query/QueryChain.h"
#include "../conn/Connection.h"

template class DbTransaction<PGTransactionData::read_committed, PGTransactionData::write_policy::read_write>;
template class DbTransaction<PGTransactionData::read_committed, PGTransactionData::write_policy::read_only>;
template class DbTransaction<PGTransactionData::repeatable_read, PGTransactionData::write_policy::read_write>;
template class DbTransaction<PGTransactionData::repeatable_read, PGTransactionData::write_policy::read_only>;
template class DbTransaction<PGTransactionData::serializable, PGTransactionData::write_policy::read_write>;
template class DbTransaction<PGTransactionData::serializable, PGTransactionData::write_policy::read_only>;

#define DECLARE_BEGIN_CMD(IL, WP)                                                                                      \
    template <> const char *DbTransaction<PGTransactionData::IL, PGTransactionData::write_policy::WP>::begin_cmd

DECLARE_BEGIN_CMD(read_committed, read_write)  = "BEGIN";
DECLARE_BEGIN_CMD(read_committed, read_only)   = "BEGIN READ ONLY";
DECLARE_BEGIN_CMD(repeatable_read, read_write) = "BEGIN ISOLATION LEVEL REPEATABLE READ";
DECLARE_BEGIN_CMD(repeatable_read, read_only)  = "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY";
DECLARE_BEGIN_CMD(serializable, read_write)    = "BEGIN ISOLATION LEVEL SERIALIZABLE";
DECLARE_BEGIN_CMD(serializable, read_only)     = "BEGIN ISOLATION LEVEL SERIALIZABLE READ ONLY";

template <PGTransactionData::isolation_level isolation, PGTransactionData::write_policy rw>
DbTransaction<isolation, rw>::DbTransaction(const DbTransaction<isolation, rw> &trans)
    : Transaction(PolicyFactory::instance()->createTransaction(this, TR_POLICY), trans.handler)
    , dummyParent("", false, false)
    , il(isolation)
    , wp(rw)
{
    if (trans.tr_impl->query)
        tr_impl->query = trans.tr_impl->query->clone();
}

template <PGTransactionData::isolation_level isolation, PGTransactionData::write_policy rw>
int DbTransaction<isolation, rw>::begin()
{
    if (!get_conn()) {
        ERROR("absent connection");
        return -1;
    }
    if (state == BEGIN) {
        auto begin_q = PolicyFactory::instance()->createQueryParam(begin_cmd, false, &dummyParent);
        begin_q->reset(get_conn());
        int ret = begin_q->exec();
        delete begin_q;
        state = BODY;
        TRANS_LOG(this, "exec: %s", begin_cmd);
        return ret > 0 ? is_pipeline() : -1;
    }
    return 1;
}

template <PGTransactionData::isolation_level isolation, PGTransactionData::write_policy rw>
int DbTransaction<isolation, rw>::execute()
{
    if (!tr_impl->query->is_finished()) {
        int ret = Transaction::execute();
        if (ret < 0)
            return -1;
        else if (ret == 1 && is_pipeline())
            return 2;
        else
            return ret;
    } else {
        return 0;
    }
}

template <PGTransactionData::isolation_level isolation, PGTransactionData::write_policy rw>
int DbTransaction<isolation, rw>::rollback()
{
    if (!get_conn()) {
        ERROR("absent connection");
        return -1;
    }
    if (state != BEGIN) {
        auto end_q = PolicyFactory::instance()->createQueryParam("ROLLBACK", false, &dummyParent);
        end_q->reset(get_conn());
        int ret = end_q->exec();
        delete end_q;
        state                     = END;
        tr_impl->pipeline_aborted = false;
        tr_impl->synced           = false;
        tr_impl->sync_sent        = false;
        if (ret)
            tr_impl->query->set_finished();
        TRANS_LOG(this, "exec: ROLLBACK");
        if (!ret)
            return -1;
        return get_conn()->getPipeStatus() == PQ_PIPELINE_ON ? 2 : 1;
    }
    return 0;
}

template <PGTransactionData::isolation_level isolation, PGTransactionData::write_policy rw>
bool DbTransaction<isolation, rw>::is_equal(Transaction *trans)
{
    if (trans->get_type() == TR_POLICY) {
        DbTransaction<isolation, rw> *dbtrans = (DbTransaction<isolation, rw> *)trans;
        return dbtrans->il == il && dbtrans->wp == wp;
    } else if (Transaction::is_equal(trans))
        return true;
    return false;
}

template <PGTransactionData::isolation_level isolation, PGTransactionData::write_policy rw>
IQuery *DbTransaction<isolation, rw>::get_current_query(bool parent)
{
    if (!tr_impl->query)
        return 0;
    if (parent)
        return tr_impl->query;
    if (!is_pipeline())
        return tr_impl->query->get_current_query();

    QueryChain *chain = dynamic_cast<QueryChain *>(tr_impl->query);
    if (!chain)
        return tr_impl->query;

    uint32_t num = chain->get_result_got();
    if (num <= 1)
        return chain->get_query(0);
    else if (num - 1 >= chain->get_size())
        return chain->get_current_query();
    return chain->get_query(num - 1);
}

template <PGTransactionData::isolation_level isolation, PGTransactionData::write_policy rw>
int DbTransaction<isolation, rw>::end()
{
    if (!get_conn()) {
        ERROR("absent connection");
        return -1;
    }
    if (state == BODY) {
        auto end_q = PolicyFactory::instance()->createQueryParam("END", false, &dummyParent);
        end_q->reset(get_conn());
        int ret = end_q->exec();
        delete end_q;
        state = END;
        TRANS_LOG(this, "exec: END");
        if (!ret)
            return -1;
        return get_conn()->getPipeStatus() == PQ_PIPELINE_ON ? 2 : 1;
    }
    return 0;
}

Transaction *createDbTransaction(ITransactionHandler *handler, PGTransactionData::isolation_level il,
                                 PGTransactionData::write_policy wp)
{
    if (il == PGTransactionData::read_committed && wp == PGTransactionData::write_policy::read_write)
        return new DbTransaction<PGTransactionData::read_committed, PGTransactionData::write_policy::read_write>(
            handler);
    else if (il == PGTransactionData::read_committed && wp == PGTransactionData::write_policy::read_only)
        return new DbTransaction<PGTransactionData::read_committed, PGTransactionData::write_policy::read_only>(
            handler);
    else if (il == PGTransactionData::repeatable_read && wp == PGTransactionData::write_policy::read_write)
        return new DbTransaction<PGTransactionData::repeatable_read, PGTransactionData::write_policy::read_write>(
            handler);
    else if (il == PGTransactionData::repeatable_read && wp == PGTransactionData::write_policy::read_only)
        return new DbTransaction<PGTransactionData::repeatable_read, PGTransactionData::write_policy::read_only>(
            handler);
    else if (il == PGTransactionData::serializable && wp == PGTransactionData::write_policy::read_write)
        return new DbTransaction<PGTransactionData::serializable, PGTransactionData::write_policy::read_write>(handler);
    else if (il == PGTransactionData::serializable && wp == PGTransactionData::write_policy::read_only)
        return new DbTransaction<PGTransactionData::serializable, PGTransactionData::write_policy::read_only>(handler);
    return 0;
}

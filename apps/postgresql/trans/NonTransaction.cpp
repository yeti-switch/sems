#include "NonTransaction.h"

NonTransaction::NonTransaction(const NonTransaction &trans)
    : Transaction(PolicyFactory::instance()->createTransaction(this, TR_NON), trans.handler)
{
    if (trans.tr_impl->query)
        tr_impl->query = trans.tr_impl->query->clone();
}

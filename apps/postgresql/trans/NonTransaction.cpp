#include "NonTransaction.h"
#include "PGTransactionImpl.h"

NonTransaction::NonTransaction(ITransactionHandler *handler)
    : Transaction(new PGTransactionImpl(this, TR_NON), handler)
{
}

NonTransaction::NonTransaction(const NonTransaction &trans)
    : Transaction(new PGTransactionImpl(this, TR_NON), trans.handler)
{
    if (trans.tr_impl->query)
        tr_impl->query = trans.tr_impl->query->clone();
}

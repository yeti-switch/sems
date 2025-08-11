#pragma once

#include "AmArg.h"

#include <string>
using std::string;

class Transaction;

struct ITransactionHandler {
    virtual ~ITransactionHandler() {}
    virtual void onSend(Transaction *conn)                            = 0;
    virtual void onCancel(Transaction *conn)                          = 0;
    virtual void onError(Transaction *trans, const string &error)     = 0;
    virtual void onErrorCode(Transaction *trans, const string &error) = 0;
    virtual void onPQError(Transaction *conn, const string &error)    = 0;
    virtual void onFinish(Transaction *conn, const AmArg &result)     = 0;
    virtual void onTuple(Transaction *conn, const AmArg &result)      = 0;
};

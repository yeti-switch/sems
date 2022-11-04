#include "Connection.h"
#include "../trans/Transaction.h"
#include <log.h>
# include <sys/socket.h>
# include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <AmUtils.h>

Connection::~Connection() {
    if(planned) delete planned;
}

void Connection::check_mode()
{
    if(isBusy()) return;
    if(pipe_status == PQ_PIPELINE_ON && !is_pipeline) exit_pipe();
    else if(pipe_status == PQ_PIPELINE_OFF && is_pipeline) start_pipe();
}

bool Connection::runTransaction(Transaction* trans)
{
    if(cur_transaction)
        return false;
    trans->reset(this);
    cur_transaction = trans;
    check();
    return true;
}

bool Connection::addPlannedTransaction(Transaction* trans)
{
    if(planned) {
        WARN("exist planned transaction, rewrite it");
        delete planned;
    }
    planned = trans;
    return true;
}

void Connection::startPipeline()
{
    is_pipeline = true;
    check_mode();
}

bool Connection::flushPipeline()
{
    if(pipe_status != PQ_PIPELINE_ON) return false;
    return flush_conn(true);
}

bool Connection::syncPipeline()
{
    if(pipe_status != PQ_PIPELINE_ON) return false;
    return sync_pipe();
}

void Connection::exitPipeline()
{
    is_pipeline = false;
    check_mode();
}

void Connection::check()
{
    if(status != CONNECTION_BAD) {
        check_conn();
    }

    if(status == CONNECTION_OK && !getConnectedTime()) {
        connected_time = time(0);
    }

    if(status == CONNECTION_OK && cur_transaction) {
        if(cur_transaction->check()) {
            //PQisBusy() returned 1 during transaction processing
            //CLASS_DBG("PQisBusy() returned 1 during transaction processing");
            handler->onSock(this, IConnectionHandler::PG_SOCK_READ);
        }
        if(cur_transaction->get_status() == Transaction::FINISH) {
            //DBG("finish transaction");
            queries_finished += cur_transaction->get_size();
            cur_transaction = 0;
            check_mode();
            if(planned) runTransaction(planned);
            planned = 0;
        }
    }
}

bool Connection::reset()
{
    disconnected_time = time(0);
    connected_time = 0;
    stopTransaction();
    if(reset_conn()) {
        check_conn();
        return true;
    }
    return false;
}

void Connection::close()
{
    disconnected_time = time(0);
    connected_time = 0;
    stopTransaction();
    close_conn();
}

void Connection::cancelTransaction()
{
    if(cur_transaction && cur_transaction->get_status() != Transaction::FINISH) {
        cur_transaction->cancel();
    }
}

void Connection::stopTransaction()
{
    if(handler && cur_transaction) handler->onStopTransaction(cur_transaction);
    cur_transaction = 0;
    delete planned;
    planned = 0;
}


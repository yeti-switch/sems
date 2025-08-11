#include "pg_log.h"
#include <sstream>

#define PG_LOG_PREFIX "pg_log: "
#define PG_LOG_MARGIN "  "

string print_pg_event(const PGExecute &ev, string prefix, string margin = string());
string print_pg_event(const PGParamExecute &ev, string prefix, string margin = string());
string print_pg_event(const PGPrepare &ev, string prefix, string margin = string());
string print_pg_event(const PGPrepareExec &ev, string prefix, string margin = string());
string print_pg_event(const PGWorkerPoolCreate &ev, string prefix, string margin = string());
string print_pg_event(const PGWorkerConfig &ev, string prefix, string margin = string());
string print_pg_event(const PGWorkerDestroy &ev, string prefix, string margin = string());
string print_pg_event(const PGSetSearchPath &ev, string prefix, string margin = string());
string print_pg_event(const PGResponse &ev, string prefix, string margin = string());
string print_pg_event(const PGResponseError &ev, string prefix, string margin = string());
string print_pg_event(const PGTimeout &ev, string prefix, string margin = string());
string print_query_data(const PGQueryData &qd, string prefix, string margin = string());
string print_query_info(const QueryInfo &qi, string prefix, string margin = string());
string print_prepare_data(const PGPrepareData &pd, string prefix, string margin = string());

/* print_pg_event PGEvent */

string pg_log::print_pg_event(AmEvent *ev)
{
    switch (ev->event_id) {
    case PGEvent::SimpleExecute:
        if (PGExecute *e = dynamic_cast<PGExecute *>(ev))
            return print_pg_event(*e, PG_LOG_PREFIX);
    case PGEvent::ParamExecute:
        if (const PGParamExecute *e = dynamic_cast<PGParamExecute *>(ev))
            return print_pg_event(*e, PG_LOG_PREFIX);
    case PGEvent::Prepare:
        if (PGPrepare *e = dynamic_cast<PGPrepare *>(ev))
            return print_pg_event(*e, PG_LOG_PREFIX);
    case PGEvent::PrepareExec:
        if (PGPrepareExec *e = dynamic_cast<PGPrepareExec *>(ev))
            return print_pg_event(*e, PG_LOG_PREFIX);
    case PGEvent::WorkerPoolCreate:
        if (auto *e = dynamic_cast<PGWorkerPoolCreate *>(ev))
            return print_pg_event(*e, PG_LOG_PREFIX);
    case PGEvent::WorkerConfig:
        if (auto *e = dynamic_cast<PGWorkerConfig *>(ev))
            return print_pg_event(*e, PG_LOG_PREFIX);
    case PGEvent::WorkerDestroy:
        if (auto *e = dynamic_cast<PGWorkerDestroy *>(ev))
            return print_pg_event(*e, PG_LOG_PREFIX);
    case PGEvent::SetSearchPath:
        if (auto *e = dynamic_cast<PGSetSearchPath *>(ev))
            return print_pg_event(*e, PG_LOG_PREFIX);
    case PGEvent::Result:
        if (auto *e = dynamic_cast<PGResponse *>(ev))
            return print_pg_event(*e, PG_LOG_PREFIX);
    case PGEvent::ResultError:
        if (auto *e = dynamic_cast<PGResponseError *>(ev))
            return print_pg_event(*e, PG_LOG_PREFIX);
    case PGEvent::Timeout:
        if (auto *e = dynamic_cast<PGTimeout *>(ev))
            return print_pg_event(*e, PG_LOG_PREFIX);
    }

    return string();
}

/* print pg event */

string print_pg_event(const PGExecute &ev, string prefix, string margin)
{
    std::stringstream ss;
    ss << prefix << "PGExecute: ";
    ss << "\n" << margin << print_query_data(ev.qdata, "qdata: ", margin + PG_LOG_MARGIN);
    return string(ss.str());
}

string print_pg_event(const PGParamExecute &ev, string prefix, string margin)
{
    std::stringstream ss;
    ss << prefix << "PGParamExecute: ";
    ss << "prepared: " << ev.prepared;
    ss << ",\n" << margin << print_query_data(ev.qdata, "qdata: ", margin + PG_LOG_MARGIN);
    return string(ss.str());
}

string print_pg_event(const PGPrepare &ev, string prefix, string margin)
{
    std::stringstream ss;
    ss << prefix << "PGPrepare: ";
    ss << "worker_name: " << ev.worker_name;
    ss << ",\n" << margin << print_prepare_data(ev.pdata, "pdata: ", margin + PG_LOG_MARGIN);
    return string(ss.str());
}

string print_pg_event(const PGPrepareExec &ev, string prefix, string margin)
{
    std::stringstream ss;
    ss << prefix << "PGPrepareExec: ";
    ss << "worker_name: " << ev.worker_name;
    ss << ", stmt: " << ev.stmt;
    ss << ", sender_id: " << ev.sender_id;
    ss << ", token: " << ev.token;
    ss << ",\n" << margin << print_query_info(ev.info, "qdata: ", margin + PG_LOG_MARGIN);
    return string(ss.str());
}

string print_pg_event(const PGWorkerPoolCreate &ev, string prefix, string margin)
{
    std::stringstream ss;
    ss << prefix << "PGWorkerPoolCreate: ";
    ss << "worker_name: " << ev.worker_name;
    ss << ", type: " << (ev.type == 0 ? "master" : "slave");
    return string(ss.str());
}

string print_pg_event(const PGWorkerConfig &ev, string prefix, string margin)
{
    std::stringstream ss;
    ss << prefix << "PGWorkerConfig: ";
    ss << "worker_name: " << ev.worker_name;
    ss << ", batch_size: " << ev.batch_size;
    ss << ", batch_timeout: " << ev.batch_timeout;
    ss << ", max_queue_length: " << ev.max_queue_length;
    ss << ", failover_to_slave: " << ev.failover_to_slave;
    ss << ", trans_wait_time: " << ev.trans_wait_time;
    ss << ", retransmit_interval: " << ev.retransmit_interval;
    ss << ", reconnect_interval: " << ev.reconnect_interval;
    ss << ", use_pipeline: " << ev.use_pipeline;
    ss << ", connection_lifetime: " << ev.connection_lifetime;

    int i = 0;
    for (auto it : ev.prepared) {
        ss << ",\n"
           << margin << print_prepare_data(it, "prepared[" + std::to_string(i) + "]: ", margin + PG_LOG_MARGIN);
        ++i;
    }

    i = 0;
    for (auto it : ev.search_pathes) {
        ss << ",\n" << margin << "search_pathes[" << i << "]: " << it;
        ++i;
    }

    i = 0;
    for (auto it : ev.reconnect_errors) {
        ss << ",\n" << margin << "reconnect_errors[" << i << "]: " << it;
        ++i;
    }

    // std::list<std::variant<PGExecute, PGParamExecute>> initial_queries;
    i = 0;
    for (const auto &initial_query : ev.initial_queries) {
        if (0 == initial_query.index()) {
            auto &e = std::get<PGExecute>(initial_query);
            ss << ",\n" << print_pg_event(e, "initial_query[" + std::to_string(i) + "]: ", margin + PG_LOG_MARGIN);
        } else {
            auto &e = std::get<PGParamExecute>(initial_query);
            ss << ",\n" << print_pg_event(e, "initial_query[" + std::to_string(i) + "]: ", margin + PG_LOG_MARGIN);
        }

        ++i;
    }

    return string(ss.str());
}

string print_pg_event(const PGWorkerDestroy &ev, string prefix, string margin)
{
    std::stringstream ss;
    ss << prefix << "PGWorkerDestroy: ";
    ss << "worker_name: " << ev.worker_name;
    return string(ss.str());
}

string print_pg_event(const PGSetSearchPath &ev, string prefix, string margin)
{
    std::stringstream ss;
    ss << prefix << "PGSetSearchPath: ";
    ss << "worker_name: " << ev.worker_name;

    int i = 0;
    for (auto it : ev.search_pathes) {
        ss << ",\n" << margin << "search_pathes[" << i << "]: " << it;
        ++i;
    }

    return string(ss.str());
}

string print_pg_event(const PGResponse &ev, string prefix, string margin)
{
    std::stringstream ss;
    ss << prefix << "PGResponse: ";
    ss << "token: " << ev.token;
    ss << ", result: " << ev.result.print();
    return string(ss.str());
}

string print_pg_event(const PGResponseError &ev, string prefix, string margin)
{
    std::stringstream ss;
    ss << prefix << "PGResponseError: ";
    ss << "token: " << ev.token;
    ss << ", error: " << ev.error;
    return string(ss.str());
}

string print_pg_event(const PGTimeout &ev, string prefix, string margin)
{
    std::stringstream ss;
    ss << prefix << "PGTimeout: ";
    ss << "token: " << ev.token;
    return string(ss.str());
}

/* print data */

string print_query_data(const PGQueryData &qd, string prefix, string margin)
{
    std::stringstream ss;
    ss << prefix << "PGQueryData: ";
    ss << "worker_name: " << qd.worker_name;
    ss << ", sender_id: " << qd.sender_id;
    ss << ", token: " << qd.token;

    int i = 0;
    for (auto it : qd.info) {
        ss << ",\n" << margin << print_query_info(it, "info[" + std::to_string(i) + "]: ", margin + PG_LOG_MARGIN);
        ++i;
    }

    return string(ss.str());
}

string print_query_info(const QueryInfo &qi, string prefix, string margin)
{
    std::stringstream ss;
    ss << prefix << "QueryInfo: ";
    ss << "query: " << qi.query;
    ss << ", single: " << qi.single;

    int i = 0;
    for (auto it : qi.params) {
        ss << ",\n" << margin << "params[" << i << "]: " << it.print();
        ++i;
    }

    return string(ss.str());
}

string print_prepare_data(const PGPrepareData &pd, string prefix, string margin)
{
    std::stringstream ss;
    ss << prefix << "PGPrepareData: ";
    ss << "stmt: " << pd.stmt;
    ss << ", query: " << pd.query;

    int i = 0;
    for (auto it : pd.oids) {
        ss << ",\n" << margin << "oids[" << i << "]: " << it;
        ++i;
    }

    i = 0;
    for (auto it : pd.sql_types) {
        ss << ",\n" << margin << "sql_types[" << i << "]: " << it;
        ++i;
    }

    return string(ss.str());
}

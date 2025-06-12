#include <ampi/PostgreSqlAPI.h>
#include <postgresql/libpq-fe.h>

namespace pg_log {
    string print_pg_event(AmEvent* ev);
    string print_pg_conn_status(const char* name,
                                ConnStatusType conn_status,
                                PostgresPollingStatusType poll_status,
                                PGpipelineStatus pipe_status);
}

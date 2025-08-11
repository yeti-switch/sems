#pragma once

#include "../PolicyFactory.h"

#include "QueryParam.h"
#include "IQueryImpl.h"
#include "IQuery.h"

#include <postgresql/libpq-fe.h>
#include <string>

class Query : public IQuery {
  protected:
    IQueryImpl *impl;
    Query(IQueryImpl *impl)
        : impl(impl)
    {
    }

  public:
    Query(const string &cmd, bool single)
        : impl(PolicyFactory::instance()->createSimpleQuery(cmd, single))
    {
    }
    ~Query() { delete impl; }

    int         exec() override;
    bool        is_single_mode() override { return impl->is_single_mode(); }
    bool        is_finished() override { return impl->is_finished(); }
    const char *get_last_error() override { return impl->get_last_error(); }
    void        reset(Connection *conn) override { impl->reset(conn); }
    std::string get_query() override { return impl->get_query(); }
    uint32_t    get_size() override { return 1; }
    IQuery     *clone() override { return new Query(impl->get_query(), impl->is_single_mode()); }
    IQuery     *get_current_query() override { return this; }
    void        set_finished() override { impl->set_finished(); }
    Connection *getConnection() override { return impl->getConnection(); }
    void        put_result() override {}
    uint32_t    get_result_got() override { return 1; };
    void        set_last_error(const char *error) override { impl->set_last_error(error); };
};

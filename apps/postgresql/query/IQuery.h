#pragma once

#include <string>
#include <cstdint>

class Connection;

struct IQuery {
    IQuery() {}
    virtual ~IQuery() {}
    virtual int         exec()                            = 0;
    virtual bool        is_single_mode()                  = 0;
    virtual bool        is_finished()                     = 0;
    virtual const char *get_last_error()                  = 0;
    virtual void        reset(Connection *conn)           = 0;
    virtual std::string get_query()                       = 0;
    virtual uint32_t    get_size()                        = 0;
    virtual IQuery     *clone()                           = 0;
    virtual IQuery     *get_current_query()               = 0;
    virtual void        set_finished()                    = 0;
    virtual Connection *getConnection()                   = 0;
    virtual void        put_result()                      = 0;
    virtual uint32_t    get_result_got()                  = 0;
    virtual void        set_last_error(const char *error) = 0;
};

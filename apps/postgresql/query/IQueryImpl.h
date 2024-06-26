#pragma once

#include <string>

class Connection;

class IQueryImpl
{
  protected:
    Connection* conn;
    std::string last_error;
    bool single_mode;
    std::string query;
    bool is_send;
    bool finished;
  public:
    IQueryImpl(const std::string& q, bool single)
      : conn(0), single_mode(single), query(q)
      , is_send(false), finished(false)
    {}
    virtual ~IQueryImpl(){}

    bool is_single_mode() { return single_mode; }
    bool is_finished() { return is_send || finished; }
    const char* get_last_error() { return last_error.c_str(); }
    void set_last_error(const char* error) { last_error = error; }
    std::string get_query() { return query; }
    void set_finished() { finished = true; }
    void reset(Connection* conn_) { conn = conn_; is_send = false; finished = false; }
    Connection* getConnection() { return conn; }

    virtual int exec() = 0;
};

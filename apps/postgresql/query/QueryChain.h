#pragma once

#include "IQuery.h"

#include <vector>

class QueryChain : public IQuery
{
    std::vector<IQuery*> childs;
    size_t current;
    bool is_sent;
    bool finished;
    int got_result;
    QueryChain()
    : current(0)
    , is_sent(false)
    , finished(false) {}
public:
    QueryChain(IQuery* first)
    : is_sent(false)
    , finished(false)
    , got_result(0){
        addQuery(first);
        current = 0;
    }
    ~QueryChain(){
        for(auto& child : childs) delete child;
    }

    int exec() override;
    void addQuery(IQuery* q);
    void removeQuery(IQuery* q);
    void reset(Connection* conn) override;
    IQuery* clone() override;
    IQuery* get_current_query() override;
    void put_result() override;
    uint32_t get_result_got() override { return got_result; }

    bool is_single_mode() override { return get_current_query()->is_single_mode(); }
    bool is_finished() override { return is_sent || finished; }
    const char* get_last_error() override { return get_current_query()->get_last_error(); }
    std::string get_query() override { return get_current_query()->get_query(); }
    void set_finished() override { finished = true; }
    uint32_t get_size() override { return (uint32_t)childs.size(); }
    IQuery* get_query(int num) { return childs[num]; }
    Connection* getConnection() override { return childs[current]->getConnection(); }
};

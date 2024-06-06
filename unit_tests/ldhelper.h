#pragma once
#include <resolv.h>

typedef typeof(&res_search) res_search_func_t;

extern res_search_func_t real_res_search;
extern res_search_func_t mock_res_search;

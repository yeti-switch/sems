#pragma once

#include "ldhelper.h"

int dns_dump_res_search(const char *dname, int cl, int type, unsigned char *answer, int anslen) __THROW;

#pragma once

#include "AmArg.h"

#include <string>
#include <vector>

using std::string;
using std::vector;

ssize_t args2redis_cmd(const AmArg &arg, char **cmd);
ssize_t args2redis_cmd(const vector<AmArg> &args, char **cmd);
void    free_redis_cmd(char *cmd);

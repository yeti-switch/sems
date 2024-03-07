#pragma once
#include <ampi/RedisApi.h>

struct Utils
{
    static int read_file_data(const string &path, string &data);
};

struct RedisScriptLoadRequest
  : AmObject
{
    const RedisScript *script;

    RedisScriptLoadRequest(const RedisScript *script)
      : script(script)
    {}
};

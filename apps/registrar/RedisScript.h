#pragma once

#include "RedisConnection.h"
#include "RedisConnectionPool.h"

#define REDIS_REPLY_SCRIPT_LOAD 0

struct RedisScript
{
    const string name;
    string hash;

    RedisScript(const string &name, const string &hash = string())
      : name(name),
        hash(hash)
    {}

    int load(RedisConnection *conn, const string &queue_name, const string &path);
    bool is_loaded() { return hash.empty() == false; }
    static int get_script_data(const string &path, string &data);
};

class RedisScriptLoader
{
  protected:
    AmSharedVar<bool> all_scripts_loaded;
    virtual void process_reply_script_load(RedisReplyEvent &event);
    virtual void script_loaded(const RedisScript *script, const char *hash) = 0;
  public:
    bool is_all_scripts_loaded() { return all_scripts_loaded.get(); }
    virtual void load_all_scripts(RedisConnection* conn = nullptr) = 0;
};

struct RedisScriptLoadRequest
  : AmObject
{
    const RedisScript *script;
    RedisScriptLoadRequest(const RedisScript *script)
      : script(script)
    {}
};

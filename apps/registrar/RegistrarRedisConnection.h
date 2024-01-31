#pragma once

#include "RedisConnectionPool.h"
#include "RedisConnection.h"
#include "RedisScript.h"
#include "Config.h"

class RegistrarRedisConnection
  : public RedisConnectionPool,
    public RedisScriptLoader,
    public Configurable
{
  private:
    bool use_functions;

    RedisScript register_script;
    RedisScript aor_lookup_script;
    RedisScript rpc_aor_lookup_script;
    RedisConnection* conn;
    RedisConnection* read_conn;

  protected:
    void on_connect(RedisConnection* c) override;
    int init_connection(cfg_t* cfg, RedisConnection*& c);
    void script_loaded(const RedisScript *script, const char *hash) override;
    void process_reply_event(RedisReplyEvent &event) override;

  public:
    RegistrarRedisConnection();
    int configure(cfg_t* cfg) override;
    void load_all_scripts(RedisConnection* conn = nullptr) override;

    bool fetch_all(AmObject *user_data, int user_type_id, const string &session_id,
        const string &registration_id);

    bool unbind_all(AmObject *user_data, int user_type_id, const string &session_id,
        const string &registration_id);

    bool bind(AmObject *user_data, int user_type_id, const string &session_id,
        const string &registration_id, const string &contact, int expires, const string &user_agent,
        const string &path, unsigned short local_if);

    bool resolve_aors(AmObject *user_data, int user_type_id, const string &session_id, std::set<string> aor_ids);
    void rpc_bind(AmObject *user_data, int user_type_id, const string &session_id, const AmArg &arg);
    void rpc_unbind(AmObject *user_data, int user_type_id, const string &session_id, const AmArg &arg);
    void rpc_resolve_aors( AmObject *user_data, int user_type_id, const string &session_id, const AmArg &arg);
};

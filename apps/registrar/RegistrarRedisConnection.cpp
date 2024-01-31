#include "RegistrarRedisConnection.h"

static const string REGISTAR_QUEUE_NAME("registrar");

RegistrarRedisConnection::RegistrarRedisConnection()
  : RedisConnectionPool("reg", REGISTAR_QUEUE_NAME),
     register_script("register_script"),
     aor_lookup_script("aor_lookup_script"),
     rpc_aor_lookup_script("rpc_aor_lookup_script"),
     conn(0)
{ }

/* Configurable */
int RegistrarRedisConnection::configure(cfg_t* cfg)
{
    auto reg_redis = cfg_getsec(cfg, CFG_SEC_REDIS);
    if(!reg_redis)
        return -1;

    use_functions = cfg_getbool(reg_redis, CFG_PARAM_USE_FUNCTIONS);
    auto reg_redis_write = cfg_getsec(reg_redis, CFG_SEC_WRITE);
    auto reg_redis_read = cfg_getsec(reg_redis, CFG_SEC_READ);
    if(!reg_redis_read || !reg_redis_write)
        return -1;

    int ret = RedisConnectionPool::init();
    if(ret)
        return -1;

    if(init_connection(reg_redis_read, read_conn) ||
       init_connection(reg_redis_write, conn))
        return -1;

    return 0;
}

void RegistrarRedisConnection::load_all_scripts(RedisConnection* conn) {
    if(use_functions) {
        all_scripts_loaded.set(true);
        return;
    }

    if((!conn && this->conn) || (conn && conn == this->conn)) {
        all_scripts_loaded.set(false);
        register_script.load(this->conn, get_queue_name(), "/etc/sems/scripts/register.lua");
    }

    if((!conn && read_conn) || (conn && conn == read_conn)) {
        all_scripts_loaded.set(false);
        aor_lookup_script.load(read_conn, get_queue_name(), "/etc/sems/scripts/aor_lookup.lua");
        rpc_aor_lookup_script.load(read_conn, get_queue_name(), "/etc/sems/scripts/rpc_aor_lookup.lua");
    }
}

void RegistrarRedisConnection::on_connect(RedisConnection* conn) {
    load_all_scripts(conn);
}

int RegistrarRedisConnection::init_connection(cfg_t* cfg, RedisConnection*& c)
{
    string host = cfg_getstr(cfg, CFG_PARAM_HOST);
    int port = cfg_getint(cfg, CFG_PARAM_PORT);

    c = addConnection(host, port);
    if(!c) return -1;

    if(cfg_size(cfg, CFG_PARAM_PASSWORD)) {
        string username;
        string password = cfg_getstr(cfg, CFG_PARAM_PASSWORD);
        if(cfg_size(cfg, CFG_PARAM_USERNAME))
            username = cfg_getstr(cfg, CFG_PARAM_USERNAME);
        c->set_auth_data(password, username);
    }

    return 0;
}

void RegistrarRedisConnection::process_reply_event(RedisReplyEvent &event)
{
    switch(event.user_type_id) {
    case REDIS_REPLY_SCRIPT_LOAD:
        process_reply_script_load(event);
        break;
    }
}

void RegistrarRedisConnection::script_loaded(const RedisScript *script, const char *hash) {
    list<RedisScript *> scripts = {&register_script, &aor_lookup_script, &rpc_aor_lookup_script};
    bool is_all_loaded = true;

    for(auto s : scripts) {
        if(s == script)
            s->hash = hash;

        if(is_all_loaded && s->is_loaded() == false)
            is_all_loaded = false;
    };

    if (all_scripts_loaded.get() != is_all_loaded)
        all_scripts_loaded.set(is_all_loaded);
}

bool RegistrarRedisConnection::fetch_all(
    AmObject* user_data,
    int user_type_id,
    const string &session_id,
    const string &registration_id)
{
    if(!use_functions && !register_script.is_loaded()) {
        ERROR("empty aor_lookup_script.hash. lua scripting error");
        return false;
    }

    return postRedisRequestFmt(
        conn,
        get_queue_name(),
        session_id,
        false,
        user_data,
        user_type_id,
        use_functions ? "FCALL %s 1 %s" : "EVALSHA %s 1 %s",
        use_functions ? "register"      : register_script.hash.c_str(),
        registration_id.c_str());
}

bool RegistrarRedisConnection::unbind_all(
    AmObject* user_data,
    int user_type_id,
    const string &session_id,
    const string &registration_id)
{
    if(!use_functions && !register_script.is_loaded()) {
        ERROR("empty aor_lookup_script.hash. lua scripting error");
        return false;
    }

    return postRedisRequestFmt(
        conn,
        get_queue_name(),
        session_id,
        false,
        user_data,
        user_type_id,
        use_functions ? "FCALL %s 1 %s 0" : "EVALSHA %s 1 %s 0",
        use_functions ? "register"        : register_script.hash.c_str(),
        registration_id.c_str());
}

bool RegistrarRedisConnection::bind(
    AmObject *user_data,
    int user_type_id,
    const string &session_id,
    const string &registration_id,
    const string &contact,
    int expires,
    const string &user_agent,
    const string &path,
    unsigned short local_if)
{
    if(!use_functions && !register_script.is_loaded()) {
        ERROR("empty aor_lookup_script.hash. lua scripting error");
        return false;
    }

    return postRedisRequestFmt(
        conn,
        get_queue_name(),
        session_id,
        false,
        user_data,
        user_type_id,
        use_functions ? "FCALL %s 1 %s %d %s %d %d %s %s" : "EVALSHA %s 1 %s %d %s %d %d %s %s",
        use_functions ? "register"                        : register_script.hash.c_str(),
        registration_id.c_str(),
        expires,
        contact.c_str(),
        AmConfig.node_id,
        local_if,
        user_agent.c_str(),
        path.c_str());
}

bool RegistrarRedisConnection::resolve_aors(
    AmObject *user_data,
    int user_type_id,
    const string &session_id,
    std::set<string> aor_ids)
{
    std::unique_ptr<char> cmd;
    size_t aors_count = aor_ids.size();

    DBG("got %ld AoR ids to resolve", aor_ids.size());

    if(!use_functions && !aor_lookup_script.is_loaded()) {
        ERROR("empty aor_lookup_script.hash. lua scripting error");
        return false;
    }

    std::ostringstream ss;
    if(use_functions) {
        ss << '*' << aors_count+3 << CRLF "$8" CRLF "FCALL_RO" CRLF "$10" CRLF << "aor_lookup" << CRLF;
    } else {
        ss << '*' << aors_count+3 << CRLF "$7" CRLF "EVALSHA" CRLF "$40" CRLF << aor_lookup_script.hash << CRLF;
    }
    //args count
    ss << '$' << len_in_chars(aors_count) << CRLF << aors_count << CRLF;
    //args
    for(const auto &id : aor_ids) {
        ss << '$' << id.length() << CRLF << id.c_str() << CRLF;
    }

    auto cmd_size = ss.str().size();
    cmd.reset(new char [cmd_size]);
    ss.str().copy(cmd.get(), cmd_size);

    //send request to redis
    return postRedisRequest(
        read_conn,
        get_queue_name(),
        session_id,
        cmd.release(),
        cmd_size,
        false, // cmd_allocated_by_redis
        false, // persistent_ctx
        user_data,
        user_type_id);
}

void RegistrarRedisConnection::rpc_bind(
    AmObject *user_data,
    int user_type_id,
    const string &session_id,
    const AmArg &arg)
{
    const string registration_id = arg2str(arg[0]);
    const string contact = arg2str(arg[1]);
    int expires = arg2int(arg[2]);
    const string path = arg.size() > 3 ? arg2str(arg[3]) : "";
    const string user_agent = arg.size() > 4 ? arg2str(arg[4]) : "";
    unsigned short local_if = arg.size() > 5 ? arg2int(arg[5]) : 0;

    if(!use_functions && !register_script.is_loaded())
        throw AmSession::Exception(500,"registrar is not enabled");

    if(false == postRedisRequestFmt(
        conn,
        get_queue_name(),
        session_id,
        false,
        user_data,
        user_type_id,
        use_functions ? "FCALL %s 1 %s %d %s %d %d %s %s" : "EVALSHA %s 1 %s %d %s %d %d %s %s",
        use_functions ? "register"                        : register_script.hash.c_str(),
        registration_id.c_str(),
        expires,
        contact.c_str(),
        AmConfig.node_id,
        local_if,
        user_agent.c_str(),
        path.c_str()))
    {
        throw AmSession::Exception(500, "failed to post bind request");
    }
}

void RegistrarRedisConnection::rpc_unbind(
    AmObject *user_data,
    int user_type_id,
    const string &session_id,
    const AmArg &arg)
{
    const string registration_id = arg2str(arg[0]);
    std::unique_ptr<char> cmd;
    size_t n;

    if(!use_functions && !register_script.is_loaded())
        throw AmSession::Exception(500,"registrar is not enabled");

    arg.assertArray();

    n = arg.size();

    std::ostringstream ss;
    if(use_functions) {
        ss << '*' << n+4 << CRLF "$5" CRLF "FCALL" CRLF "$8" CRLF << "register" << CRLF;
    } else {
        ss << '*' << n+4 << CRLF "$7" CRLF "EVALSHA" CRLF "$40" CRLF << register_script.hash << CRLF;
    }

    ss << '$' << '1' << CRLF << '1' << CRLF; // keys count
    ss << '$' << registration_id.length() << CRLF << registration_id.c_str() << CRLF; // reg id
    ss << '$' << '1' << CRLF << '0' << CRLF; // expires

    if(arg.size() > 1) {
        string contact = arg2str(arg[1]);
        ss << '$' << contact.length() << CRLF << contact.c_str() << CRLF; // contact
    }

    auto cmd_size = ss.str().size();
    cmd.reset(new char [cmd_size]);
    ss.str().copy(cmd.get(), cmd_size);


    if(false==postRedisRequest(
        read_conn,
        get_queue_name(),
        session_id,
        cmd.release(),
        cmd_size,
        false, // cmd_allocated_by_redis
        false, // persistent_ctx
        user_data,
        user_type_id))
    {
        throw AmSession::Exception(500, "failed to post unbind request");
    }
}

void RegistrarRedisConnection::rpc_resolve_aors(
    AmObject *user_data,
    int user_type_id,
    const string &session_id,
    const AmArg &arg)
{
    std::unique_ptr<char> cmd;
    size_t n, i;

    if(!use_functions && !rpc_aor_lookup_script.is_loaded())
        throw AmSession::Exception(500,"registrar is not enabled");

    arg.assertArray();

    n = arg.size();

    std::ostringstream ss;
    if(use_functions) {
        ss << '*' << n+3 << CRLF "$8" CRLF "FCALL_RO" CRLF "$14" CRLF << "rpc_aor_lookup" << CRLF;
    } else {
        ss << '*' << n+3 << CRLF "$7" CRLF "EVALSHA" CRLF "$40" CRLF << rpc_aor_lookup_script.hash << CRLF;
    }
    //keys count
    ss << '$' << len_in_chars(n) << CRLF << n << CRLF;
    //keys
    for(i = 0; i < n; i++) {
        const char* id = arg[i].asCStr();
        ss << '$' << strlen(id) << CRLF << id << CRLF;
    }

    auto cmd_size = ss.str().size();
    cmd.reset(new char [cmd_size]);
    ss.str().copy(cmd.get(), cmd_size);

    if(false==postRedisRequest(
        read_conn,
        get_queue_name(),
        session_id,
        cmd.release(),
        cmd_size,
        false, // cmd_allocated_by_redis
        false, // persistent_ctx
        user_data,
        user_type_id))
    {
        throw AmSession::Exception(500, "failed to post rpc_aor_lookup_script request");
    }
}


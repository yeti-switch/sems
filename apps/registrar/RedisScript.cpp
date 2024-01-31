#include "RedisScript.h"
#include <fstream>

int RedisScript::load(RedisConnection *conn, const string &queue_name, const string &path)
{
    string data;
    if(get_script_data(path, data) < 0)
        return -1;

    postRedisRequestFmt(conn, queue_name, queue_name, false,
        new RedisScriptLoadRequest(this), REDIS_REPLY_SCRIPT_LOAD,
        "SCRIPT LOAD %s", data.c_str());

    return 0;
}

int RedisScript::get_script_data(const string &path, string &data)
{
    try {
        std::ifstream f(path);
        if(!f) {
            ERROR("failed to open: %s", path.c_str());
            return -1;
        }

        data = string((std::istreambuf_iterator<char>(f)),
                      (std::istreambuf_iterator<char>()));
    } catch(...) {
        ERROR("failed to load %s", path.c_str());
        return -1;
    }
    return 0;
}

void RedisScriptLoader::process_reply_script_load(RedisReplyEvent &event)
{
    if(event.result != RedisReplyEvent::SuccessReply)
        return;

    auto script_req = dynamic_cast<RedisScriptLoadRequest *>(event.user_data.get());
    if(!script_req)
        return;

    auto script = script_req->script;
    if(!script)
        return;

    if(event.data.getType() != AmArg::CStr) {
        ERROR("script '%s' loaded hash with wrong type", script->name.c_str());
        return;
    }

    const char* hash = event.data.asCStr();
    if(!hash) {
        ERROR("script '%s' loaded hash is nil", script->name.c_str());
        return;
    }

    DBG("script '%s' loaded with hash '%s'", script->name.c_str(), hash);
    script_loaded(script, hash);
}

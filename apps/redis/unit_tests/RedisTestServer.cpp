#include "RedisTestServer.h"
#include "../RedisInstance.h"
#include "../RedisScript.h"
#include "../RedisUtils.h"

#include <hiredis/read.h>
#include <stdarg.h>

static string role_redis_cmd{ "*1\r\n$4\r\nROLE\r\n" };
static AmArg  role_redis_cmd_reply{ { "master" } };

RedisTestServer::RedisTestServer()
    : response_enabled(true)
{
}

void RedisTestServer::addCommandResponse(const vector<AmArg> &args, int status, AmArg response)
{
    char   *command  = nullptr;
    ssize_t cmd_size = args2redis_cmd(args, &command);

    if (cmd_size > 0) {
        statuses.emplace(command, status);
        if (status != REDIS_REPLY_STATUS && !isArgUndef(response))
            addResponse(command, response);
    }

    if (command)
        free_redis_cmd(command);
}

void RedisTestServer::addCommandResponse(const string &cmd, int status, AmArg response, ...)
{
    va_list args;
    va_start(args, response);
    char *command;
    redis::redisvFormatCommand(&command, cmd.c_str(), args);
    statuses.emplace(command, status);
    if (status != REDIS_REPLY_STATUS && !isArgUndef(response))
        addResponse(command, response);
    redis::redisFreeCommand(command);
    va_end(args);
}

void RedisTestServer::addFormattedCommandResponse(const string &cmd, int status, AmArg response)
{
    statuses.insert(std::make_pair(cmd, status));
    if (status != REDIS_REPLY_STATUS && !isArgUndef(response))
        addResponse(cmd, response);
}

void RedisTestServer::addTail(const string &cmd, int sec, ...)
{
    va_list args;
    va_start(args, sec);
    char *command;
    redis::redisvFormatCommand(&command, cmd.c_str(), args);
    TestServer::addTail(command, sec);
    redis::redisFreeCommand(command);
    va_end(args);
}

void RedisTestServer::addLoadScriptCommandResponse(const string &path, const string &hash)
{
    string data;
    if (Utils::read_file_data(path, data) == 0)
        addCommandResponse("SCRIPT LOAD %s", REDIS_REPLY_STRING, AmArg(hash), data.c_str());
}

int RedisTestServer::getStatus(const string &cmd)
{
    if (response_enabled.get() == false)
        response_enabled.wait_for();

    if (cmd == role_redis_cmd)
        return REDIS_REPLY_ARRAY;

    if (statuses.find(cmd) != statuses.end()) {
        return statuses[cmd];
    }
    return REDIS_REPLY_NIL;
}

bool RedisTestServer::getResponse(const string &cmd, AmArg &res)
{
    if (response_enabled.get() == false)
        response_enabled.wait_for();

    if (cmd == role_redis_cmd) {
        res = role_redis_cmd_reply;
        return true;
    }

    while (checkTail(cmd)) {
    }
    return TestServer::getResponse(cmd, res);
}

void RedisTestServer::clear()
{
    statuses.clear();
    TestServer::clear();
}

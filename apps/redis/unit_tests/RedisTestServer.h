#pragma once

#include <unit_tests/TestServer.h>
#include <AmThread.h>
#include <map>
#include <string>

#define REDIS_TEST_REPLY_STRING 1
#define REDIS_TEST_REPLY_ARRAY 2
#define REDIS_TEST_REPLY_INTEGER 3
#define REDIS_TEST_REPLY_NIL 4
#define REDIS_TEST_REPLY_STATUS 5
#define REDIS_TEST_REPLY_ERROR 6

using std::string;
using std::map;

class RedisTestServer : protected TestServer
{
    map<string, int> statuses;
public:
    AmCondition<bool> response_enabled;

    RedisTestServer();
    void addCommandResponse(const vector<AmArg>& args, int status, AmArg response);
    void addCommandResponse(const string& cmd, int status, AmArg response, ...);
    void addFormattedCommandResponse(const string& cmd, int status, AmArg response);
    void addTail(const string& cmd, int sec, ...);
    void addLoadScriptCommandResponse(const string &path, const string &hash);
    int getStatus(const string& cmd);
    bool getResponse(const string& cmd, AmArg& res);
    void clear();
};

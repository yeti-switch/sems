#ifndef REDIS_APP_H
#define REDIS_APP_H

#include "AmEvent.h"
#include <memory>
#include <string>

using std::string;

#define REDIS_APP_QUEUE  "redis"

class RedisEvent : public AmEvent
{
public:
    string conn_id;
    enum Type {
        AddConnection = 0,
        ConnectionState,
        Reply,
        Request,
        RequestMulti,

        MaxType
    };

    RedisEvent(int event_id, const string& conn_id)
        : AmEvent(event_id), conn_id(conn_id)
    {}
};

struct RedisScript
{
    string name;
    string hash;
    string path;

    RedisScript(const string &name, const string &path)
      : name(name), path(path)
    {}

    bool is_loaded() const { return hash.empty() == false; }
};

struct RedisConnectionInfo
{
    string host;
    int port;
    string username;
    string password;
    vector<RedisScript> scripts;

    RedisConnectionInfo()
      : host(), port(), username(), password(), scripts()
    {}

    RedisConnectionInfo(const string &host, const int port,
        const string &username = string(), const string &password = string(),
        const vector<RedisScript> &scripts = {})
      : host(host), port(port), username(username), password(password),
        scripts(scripts)
    {}
};

class RedisAddConnection
: public RedisEvent
{
public:
    RedisConnectionInfo info;
    string session_id;

    RedisAddConnection(const string &session_id, const string &conn_id,
        const RedisConnectionInfo &info)
      : RedisEvent(AddConnection, conn_id),
        info(info), session_id(session_id)
    {}
};

class RedisConnectionState
: public RedisEvent
{
public:
    enum RedisConnState{
        Connected,
        Disconnected
    } state;
    RedisConnectionInfo info;

    RedisConnectionState(const string &conn_id, RedisConnState state, const RedisConnectionInfo &info)
      : RedisEvent(ConnectionState, conn_id),
        state(state), info(info) {}
};

struct RedisRequest
  : public RedisEvent
{
    string session_id;
    vector<AmArg> args;

    //onwership will be transferred to RedisReplyEvent via redisReplyCtx
    std::unique_ptr<AmObject> user_data;
    int user_type_id;
    bool persistent_ctx;

    RedisRequest(RedisRequest &req)
      : RedisEvent(req.event_id, req.conn_id),
        session_id(req.session_id), args(req.args),
        user_data(req.user_data.release()), user_type_id(req.user_type_id),
        persistent_ctx(req.persistent_ctx)
    {}

    RedisRequest(string session_id, string conn_id, const vector<AmArg>& args,
        AmObject *user_data = nullptr, int user_type_id = 0, bool persistent_ctx = false, bool multi = false)
      : RedisEvent(multi ? RedisEvent::RequestMulti : RedisEvent::Request, conn_id),
        session_id(session_id), args(args),
        user_data(user_data), user_type_id(user_type_id),
        persistent_ctx(persistent_ctx)
    {}
};

struct RedisReply : public RedisEvent
{
    enum result_type {
        SuccessReply = 0,
        ErrorReply,
        StatusReply,
        IOError,
        NotConnected,
        FailedToSend
    } result;

    AmArg data;
    std::unique_ptr<AmObject> user_data;
    int user_type_id;

    RedisReply(const string& conn_id, result_type result, const AmArg& rdata,
        std::unique_ptr<AmObject>& udata, int utype_id)
    : RedisEvent(RedisEvent::Reply, conn_id), result(result), data(rdata),
        user_data(udata.release()), user_type_id(utype_id) {}
    ~RedisReply() {}
    static string resultStr(result_type type) {
      switch(type) {
        case SuccessReply:
          return "SuccessReply";
        case ErrorReply:
          return "ErrorReply";
        case StatusReply:
          return "StatusReply";
        case IOError:
          return "IOError";
        case NotConnected:
          return "NotConnected";
        case FailedToSend:
          return "FailedToSend";
      }
      return "";
    }
};

#endif/*REDIS_APP_H*/

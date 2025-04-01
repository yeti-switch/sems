#include "RedisUtils.h"
#include "log.h"
#include "RedisInstance.h"

#include <sstream>

/* private helpers */

static void append_args(vector<string> &args, const AmArg &child)
{
    switch(child.getType()) {
    case AmArg::CStr:
        args.emplace_back(std::string(child.asCStr()));
        break;
    case AmArg::Int: {
        std::ostringstream strs;
        strs << child.asInt();
        args.emplace_back(strs.str());
        break;
    }
    case AmArg::LongLong:  {
        std::ostringstream strs;
        strs << child.asLongLong();
        args.emplace_back(strs.str());
        break;
    }
    case AmArg::Double: {
        std::ostringstream strs;
        strs << child.asDouble();
        args.emplace_back(strs.str());
        break;
    }
    default:  DBG("Unsupported arg type %s", child.getTypeStr());
    }
}

static ssize_t args2redis_cmd(const vector<string>& args, char **cmd)
{
    vector<const char*> argv(args.size());
    vector<size_t> argvlen(args.size());
    for(unsigned i = 0; i < args.size(); ++i) {
        argv[i] = args[i].c_str();
        argvlen[i] = args[i].length();
    }

    return redis::redisFormatCommandArgv(cmd, args.size(), argv.data(), argvlen.data());
}

/* utils */

ssize_t args2redis_cmd(const AmArg& arg, char **cmd)
{
    vector<string> str_args;

    for(size_t i = 0; i < arg.size(); i++)
        append_args(str_args, arg[i]);

    return args2redis_cmd(str_args, cmd);
}

ssize_t args2redis_cmd(const vector<AmArg>& args, char **cmd)
{
    vector<string> str_args;

    for(const auto &a: args)
        append_args(str_args, a);

    return args2redis_cmd(str_args, cmd);
}

void free_redis_cmd(char *cmd)
{
    redis::redisFreeCommand(cmd);
}

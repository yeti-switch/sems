#include "ModRedis.h"
#include "log.h"
#include "AmUtils.h"

#include "DSMSession.h"
#include "AmSession.h"
#include "AmConfigReader.h"
#include "AmUtils.h"

#include "RedisPool.h"

#include <sstream>

#define KEY_OUT "redis.out"

SC_EXPORT(RedisModule);

RedisModule::RedisModule() {}
RedisModule::~RedisModule() {}

int RedisModule::preload() {
	AmConfigReader cfg;

	if(0!=cfg.loadPluginConf("redis")){
		ERROR("can't load redis config");
		return -1;
	}

	RedisPool *p = RedisPool::instance();
	if(!p) {
		ERROR("can't get redis connection pool instance");
		return -1;
	}
	if(0!=p->configure(cfg)){
		ERROR("can't configure redis connection pool");
		return -1;
	}
	p->start();
	return 0;
}

DSMAction* RedisModule::getAction(const string& from_str) {
	DBG("%s \\(-_-)/",FUNC_NAME);

	string cmd;
	string params;
	splitCmd(from_str, cmd, params);

	DEF_CMD("redis.select", SCRedisCmdAction);
	DEF_CMD("redis.perform", SCRedisCmdNoResultAction);

	return NULL;
}

DSMCondition* RedisModule::getCondition(const string& from_str) {
	return NULL;
}


string Reply2String(redisReply *r) {
	string s;
	switch(r->type){
	case REDIS_REPLY_NIL:
	case REDIS_REPLY_ERROR:
		s = "";
		break;
	case REDIS_REPLY_INTEGER:
		s = longlong2str(r->integer);
		break;
	case REDIS_REPLY_STRING:
		s = r->str;
		break;
	case REDIS_REPLY_ARRAY: {
		std::stringstream ss;
		unsigned int i = 0;
		for(;i<r->elements-1;i++)
			ss << Reply2String(r->element[i]) << ',';
		ss << Reply2String(r->element[i]);
		s = ss.str();
		} break;
	default:
		ERROR("unsupported reply for reply %p type %d from redis",r,r->type);
		s = "";
	}
	return s;
}

bool redis_cmd(DSMSession* sc_sess, const string& cmd, bool get_result) {
	redisContext *ctx = NULL;
	redisReply *reply = NULL;
	RedisPool *pool = RedisPool::instance();

	ctx = pool->getConnection();
	if(!ctx){
		sc_sess->SET_ERRNO("can't get connection");
		return false;
	}

	redisAppendCommand(ctx,cmd.c_str());

	int state = redisGetReply(ctx,(void **)&reply);
	if(state!=REDIS_OK){
		ERROR("got server error reply");
		if(reply) freeReplyObject(reply);
		sc_sess->SET_ERRNO("server error");
		pool->putConnection(ctx,RedisPool::CONN_STATE_ERR);
		return false;
	}

	if(reply->type==REDIS_REPLY_ERROR){
		ERROR("got error from redis: %s",reply->str);
		freeReplyObject(reply);
		sc_sess->SET_ERRNO(reply->str);
		pool->putConnection(ctx,RedisPool::CONN_STATE_OK);
		return false;
	}

	pool->putConnection(ctx,RedisPool::CONN_STATE_OK);

	if(!get_result){
		freeReplyObject(reply);
		sc_sess->SET_ERRNO(DSM_ERRNO_OK);
		return true;
	}

	sc_sess->var[KEY_OUT] = Reply2String(reply);

	freeReplyObject(reply);
	sc_sess->SET_ERRNO(DSM_ERRNO_OK);
	return true;
}

EXEC_ACTION_START(SCRedisCmdAction) {
	sc_sess->var.erase(KEY_OUT);
	return redis_cmd(sc_sess, resolveVars(arg, sess, sc_sess, event_params), true);
} EXEC_ACTION_END;

EXEC_ACTION_START(SCRedisCmdNoResultAction) {
	return redis_cmd(sc_sess, resolveVars(arg, sess, sc_sess, event_params), false);
} EXEC_ACTION_END;

#include "RedisPool.h"
#include "log.h"

#include <signal.h>

#define REDIS_CONN_TIMEOUT 5

_RedisPool::_RedisPool():
	tostop(false),
	failed_ready(true),
	active_ready(false),
	failed_count(0)
{}

_RedisPool::~_RedisPool()
{}

int _RedisPool::configure(const AmConfigReader &cfg_reader)
{
	cfg.host = cfg_reader.getParameter("redis_host","127.0.0.1");
	cfg.port = cfg_reader.getParameterInt("redis_port",6379);
	cfg.pool_size = cfg_reader.getParameterInt("redis_pool_size",1);
	cfg.active_timeout = cfg_reader.getParameterInt("redis_timeout",100);
	return 0;
}

void _RedisPool::run()
{
	redisContext *ctx = NULL;
	std::list<redisContext *> c;

	setThreadName("mod_redis_pool");

	conn_mtx.lock();
		unsigned int active_count = active_ctxs.size();
		while(active_count < cfg.pool_size){
			timeval timeout = { REDIS_CONN_TIMEOUT, 0 };
			ctx = redisConnectWithTimeout(cfg.host.c_str(),cfg.port,timeout);
			if(ctx != NULL && ctx->err){
				redisFree(ctx);
				ERROR("failed conn to redis server %s:%d", cfg.host.c_str(), cfg.port);
				kill(getpid(),SIGTERM); //commit suicide
				return;
			} else {
				active_ctxs.push_back(ctx);
				active_count++;
			}
		}
	conn_mtx.unlock();
	INFO("redis pool successfully connected");

	while(!tostop){
		failed_ready.wait_for();
		if(tostop) break;

		conn_mtx.lock();
			c.swap(failed_ctxs);
		conn_mtx.unlock();

		if(c.empty()){
			failed_ready.set(false);
			continue;
		}

		while(!c.empty()){
			if(tostop)
				break;
			ctx = c.front();
			c.pop_front();
			if(reconnect(ctx)){
				conn_mtx.lock();
					active_ctxs.push_back(ctx);
					failed_count--;
				conn_mtx.unlock();
				active_ready.set(true);
			} else {
				c.push_back(ctx);
				DBG("[%p] can't reconnect sleep %us",this,5);
				sleep(5);
			}
		}
		conn_mtx.lock();
			if(!failed_count) INFO("all redis connections were successfully reconnected");
			failed_ready.set(failed_count>0);
		conn_mtx.unlock();
	}
}

void _RedisPool::on_stop()
{
	redisContext *ctx;

	tostop = true;
	failed_ready.set(true);

	conn_mtx.lock();
		while(!active_ctxs.empty()){
			ctx = active_ctxs.front();
			active_ctxs.pop_front();
			redisFree(ctx);
		}
	conn_mtx.unlock();

	conn_mtx.lock();
		while(!failed_ctxs.empty()){
			ctx = failed_ctxs.front();
			failed_ctxs.pop_front();
			redisFree(ctx);
		}
	conn_mtx.unlock();
}

redisContext *_RedisPool::getConnection(unsigned int timeout)
{
	redisContext *ctx = NULL;

	timeout = timeout > 0 ? timeout : cfg.active_timeout;

	while(ctx==NULL){

		conn_mtx.lock();
		if(active_ctxs.size()){
			ctx = active_ctxs.front();
			active_ctxs.pop_front();
			active_ready.set(!active_ctxs.empty());
		}
		conn_mtx.unlock();

		if(ctx==NULL){
			conn_mtx.lock();
			bool all_failed = cfg.pool_size == failed_count;
			conn_mtx.unlock();
			if (all_failed){
				ERROR("all connections failed");
				break;
			}
			if(!active_ready.wait_for_to(timeout)){
				DBG("timeout waiting for an active connection (waited %ums)",timeout);
				break;
			}
		}
	}
	return ctx;
}

void _RedisPool::putConnection(redisContext *ctx,ConnReturnState state)
{
	switch(state){
	case CONN_STATE_OK:
		conn_mtx.lock();
		active_ctxs.push_back(ctx);
		conn_mtx.unlock();
		break;
	case CONN_STATE_ERR:
		conn_mtx.lock();
		failed_ctxs.push_back(ctx);
		failed_count++;
		conn_mtx.unlock();
		failed_ready.set(true);
		break;
	}
}

bool _RedisPool::reconnect(redisContext *&ctx){
	if(ctx!=NULL){
		redisFree(ctx);
		ctx = NULL;
	}

	timeval timeout = { REDIS_CONN_TIMEOUT, 0 };
	ctx = redisConnectWithTimeout(cfg.host.c_str(),cfg.port,timeout);
	if (ctx != NULL && ctx->err) {
		ERROR("[%p] %s() can't connect: %d <%s>",this,FUNC_NAME,ctx->err,ctx->errstr);
		redisFree(ctx);
		ctx = NULL;
		return false;
	}
	return true;
}


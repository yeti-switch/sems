#ifndef _REDIS_POOL_H
#define _REDIS_POOL_H

#include "AmConfigReader.h"
#include "AmThread.h"

#include "hiredis/hiredis.h"

#include <list>
#include <singleton.h>

class _RedisPool : public AmThread {

	AmMutex conn_mtx;

	std::list<redisContext *>active_ctxs;
	std::list<redisContext *>failed_ctxs;

	AmCondition <bool>failed_ready;
	AmCondition <bool>active_ready;

	bool tostop;
	unsigned int failed_count;

	struct {
		string host;
		int port;
		unsigned int pool_size;
		unsigned int active_timeout;
	} cfg;

	bool reconnect(redisContext *&ctx);

  protected:
	_RedisPool();
	~_RedisPool();

  public:
	enum ConnReturnState {
		CONN_STATE_OK,
		CONN_STATE_ERR
	};

	int configure(const AmConfigReader &cfg_reader);

	void run();
	void on_stop();

	redisContext *getConnection(unsigned int timeout = 0);
	void putConnection(redisContext *,ConnReturnState state);
};

typedef singleton<_RedisPool> RedisPool;

#endif

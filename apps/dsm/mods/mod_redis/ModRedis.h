#ifndef _MOD_REDIS_H
#define _MOD_REDIS_H

#include "DSMModule.h"
#include "DSMSession.h"

class RedisModule : public DSMModule {
  public:
	RedisModule();
	~RedisModule();

	int preload();
	DSMAction* getAction(const string& from_str);
	DSMCondition* getCondition(const string& from_str);
};

DEF_ACTION_1P(SCRedisCmdAction);
DEF_ACTION_1P(SCRedisCmdNoResultAction);

#endif

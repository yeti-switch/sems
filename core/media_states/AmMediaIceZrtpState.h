#pragma once

#include "AmMediaIceState.h"
#include "AmMediaZrtpState.h"

class AmMediaIceZrtpState
  : public AmMediaIceState, public AmMediaZrtpState
{
public:
    AmMediaIceZrtpState(AmMediaTransport *transport);
    AmMediaState* init(const AmArg& args) override;
    AmMediaState* update(const AmArg& args) override;
    AmMediaState* allowStunConnection(sockaddr_storage* remote_addr, uint32_t priority) override;
    AmMediaState* onSrtpKeysAvailable() override;
    const char* state2str() override;
};

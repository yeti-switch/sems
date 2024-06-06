#pragma once

#include "AmMediaIceState.h"
#include "AmMediaSrtpState.h"

class AmMediaIceSrtpState
  : public AmMediaIceState, public AmMediaSrtpState
{
public:
    AmMediaIceSrtpState(AmMediaTransport *transport);
    AmMediaState* init(const AmArg& args) override;
    AmMediaState* update(const AmArg& args) override;
    AmMediaState* allowStunConnection(sockaddr_storage* remote_addr, uint32_t priority) override;
    AmMediaState* onSrtpKeysAvailable() override;
    const char* state2str() override;
};

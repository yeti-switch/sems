#pragma once

#include "AmMediaRtpState.h"
#include "AmMediaIceState.h"

class AmMediaIceRtpState
  : public AmMediaIceState, public AmMediaRtpState
{
public:
    AmMediaIceRtpState(AmMediaTransport *transport);
    AmMediaState* init(const AmArg& args) override;
    AmMediaState* update(const AmArg& args) override;
    AmMediaState* allowStunConnection(sockaddr_storage* remote_addr, uint32_t priority) override;
    const char* state2str() override;
};

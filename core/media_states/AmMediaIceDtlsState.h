#pragma once

#include "AmMediaIceState.h"
#include "AmMediaDtlsState.h"

class AmMediaIceDtlsState
  : public AmMediaIceState, public AmMediaDtlsState
{
public:
    AmMediaIceDtlsState(AmMediaTransport *transport);
    AmMediaState* init(const AmArg& args) override;
    AmMediaState* update(const AmArg& args) override;
    AmMediaState* allowStunConnection(sockaddr_storage* remote_addr, uint32_t priority) override;
    AmMediaState* onSrtpKeysAvailable() override;
    const char* state2str() override;
};

#pragma once

#include "AmMediaIceState.h"
#include "AmMediaDtlsState.h"

class AmMediaIceDtlsState
  : public AmMediaIceState, public AmMediaDtlsState
{
public:
    AmMediaIceDtlsState(AmMediaTransport *transport);
    AmMediaState* init(const AmMediaStateArgs& args) override;
    AmMediaState* update(const AmMediaStateArgs& args) override;
    AmMediaState* onSrtpKeysAvailable() override;
    const char* state2str() override;

protected:
    AmMediaState* nextState() override;
};

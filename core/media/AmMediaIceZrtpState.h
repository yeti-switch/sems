#pragma once

#include "AmMediaIceState.h"
#include "AmMediaZrtpState.h"

class AmMediaIceZrtpState
  : public AmMediaIceState, public AmMediaZrtpState
{
public:
    AmMediaIceZrtpState(AmMediaTransport *transport);
    AmMediaState* init(const AmMediaStateArgs& args) override;
    AmMediaState* update(const AmMediaStateArgs& args) override;
    AmMediaState* onSrtpKeysAvailable() override;
    const char* state2str() override;

protected:
    AmMediaState* nextState();
};

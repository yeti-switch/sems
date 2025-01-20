#pragma once

#include "AmMediaIceState.h"
#include "AmMediaUdptlState.h"

class AmMediaIceUdptlState
  : public AmMediaIceState, public AmMediaUdptlState
{
public:
    AmMediaIceUdptlState(AmMediaTransport *transport);
    AmMediaState* init(const AmMediaStateArgs& args) override;
    AmMediaState* update(const AmMediaStateArgs& args) override;
    const char* state2str() override;

protected:
    AmMediaState* nextState() override;
};


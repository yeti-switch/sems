#pragma once

#include "AmMediaSecureUdptlState.h"
#include "AmMediaIceState.h"

class AmMediaIceSecureUdptlState
  : public AmMediaIceState, public AmMediaSecureUdptlState
{
public:
    AmMediaIceSecureUdptlState(AmMediaTransport *transport);
    AmMediaState* init(const AmMediaStateArgs& args) override;
    AmMediaState* update(const AmMediaStateArgs& args) override;
    void addConnections(const AmMediaStateArgs& args) override;
    const char* state2str() override;

protected:
    AmMediaState* nextState() override;
};


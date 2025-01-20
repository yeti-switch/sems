#pragma once

#include "AmMediaState.h"

class AmMediaSecureUdptlState
  : virtual public AmMediaState
{
public:
    AmMediaSecureUdptlState(AmMediaTransport *transport);
    AmMediaState* init(const AmMediaStateArgs& args) override;
    void addConnections(const AmMediaStateArgs& args) override;
    const char* state2str() override;
};

#pragma once

#include "AmMediaState.h"

class AmMediaSecureUdptlState
  : public AmMediaState
{
public:
    AmMediaSecureUdptlState(AmMediaTransport *transport);
    AmMediaState* init(const AmArg& args) override;
    const char* state2str() override;
};

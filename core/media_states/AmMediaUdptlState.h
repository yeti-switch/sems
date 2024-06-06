#pragma once

#include "AmMediaState.h"

class AmMediaUdptlState
  : public AmMediaState
{
public:
    AmMediaUdptlState(AmMediaTransport *transport);
    AmMediaState* init(const AmArg& args) override;
    const char* state2str() override;
};

#pragma once

#include "AmMediaState.h"

class AmMediaRtpState
  : public virtual AmMediaState
{
public:
    AmMediaRtpState(AmMediaTransport *transport);
    AmMediaState* init(const AmArg& args) override;
    AmMediaState* update(const AmArg& args) override;
    const char* state2str() override;
};

#pragma once

#include "AmMediaState.h"

class AmMediaRtpState
  : public virtual AmMediaState
{
public:
    AmMediaRtpState(AmMediaTransport *transport);
    void addConnections(const AmMediaStateArgs& args) override;
    void updateConnections(const AmMediaStateArgs& args) override;
    const char* state2str() override;
};

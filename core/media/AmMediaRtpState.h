#pragma once

#include "AmMediaState.h"

class AmMediaRtpState
  : public virtual AmMediaState
{
public:
    AmMediaRtpState(AmMediaTransport *transport);
    AmMediaState* update(const AmMediaStateArgs& args) override;
    void addConnections(const AmMediaStateArgs& args) override;
    void updateConnections(const AmMediaStateArgs& args) override;
    const char* state2str() override;
};

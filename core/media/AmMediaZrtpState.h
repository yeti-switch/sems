#pragma once

#include "AmMediaSrtpState.h"

class AmMediaZrtpState
  : public virtual AmMediaSrtpState
{
public:
    AmMediaZrtpState(AmMediaTransport *transport);
    AmMediaState* init(const AmMediaStateArgs& args) override;
    AmMediaState* update(const AmMediaStateArgs& args) override;
    AmMediaState* onSrtpKeysAvailable() override;
    void addConnections(const AmMediaStateArgs& args) override;
    void updateConnections(const AmMediaStateArgs& args) override;
    const char* state2str() override;
};

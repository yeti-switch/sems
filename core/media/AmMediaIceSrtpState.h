#pragma once

#include "AmMediaIceState.h"
#include "AmMediaSrtpState.h"

class AmMediaIceSrtpState
  : public AmMediaIceState, public AmMediaSrtpState
{
public:
    AmMediaIceSrtpState(AmMediaTransport *transport);
    AmMediaState* init(const AmMediaStateArgs& args) override;
    AmMediaState* update(const AmMediaStateArgs& args) override;
    AmMediaState* onSrtpKeysAvailable() override;
    void updateConnections(const AmMediaStateArgs & args) override;
    const char* state2str() override;

protected:
    AmMediaState* nextState();
};

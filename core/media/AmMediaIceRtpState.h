#pragma once

#include "AmMediaRtpState.h"
#include "AmMediaIceState.h"

class AmMediaIceRtpState : public AmMediaIceState, public AmMediaRtpState {
  public:
    AmMediaIceRtpState(AmMediaTransport *transport);
    AmMediaState *init(const AmMediaStateArgs &args) override;
    AmMediaState *update(const AmMediaStateArgs &args) override;
    const char   *state2str() override;

  protected:
    AmMediaState *nextState() override;
};

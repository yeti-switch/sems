#pragma once

#include "AmMediaIceState.h"
#include "AmMediaZrtpState.h"

class AmMediaIceZrtpState : public AmMediaIceState, public AmMediaZrtpState {
  public:
    AmMediaIceZrtpState(AmMediaTransport *transport);
    AmMediaState *init(const AmMediaStateArgs &args) override;
    AmMediaState *update(const AmMediaStateArgs &args) override;
    AmMediaState *onSrtpKeysAvailable(uint8_t transport_type, uint16_t srtp_profile, const string &local_key,
                                      const string &remote_key) override;
    const char   *state2str() override;

  protected:
    AmMediaState *nextState() override;
};

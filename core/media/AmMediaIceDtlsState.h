#pragma once

#include "AmMediaIceState.h"
#include "AmMediaDtlsState.h"

class AmMediaIceDtlsState : public AmMediaIceState, public AmMediaDtlsState {
  public:
    AmMediaIceDtlsState(AmMediaTransport *transport);
    AmMediaState *init(const AmMediaStateArgs &args) override;
    AmMediaState *update(const AmMediaStateArgs &args) override;
    AmMediaState *onSrtpKeysAvailable(uint8_t transport_type, uint16_t srtp_profile, const string &local_key,
                                      const string &remote_key) override;
    const char   *state2str() override;

  protected:
    AmMediaState *nextState() override;
};

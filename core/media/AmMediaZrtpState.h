#pragma once

#include "AmMediaSrtpState.h"

class AmMediaZrtpState : public virtual AmMediaSrtpState {
  public:
    AmMediaZrtpState(AmMediaTransport *transport);
    AmMediaState *init(const AmMediaStateArgs &args) override;
    AmMediaState *update(const AmMediaStateArgs &args) override;
    AmMediaState *onSrtpKeysAvailable(uint8_t transport_type, uint16_t srtp_profile, const string &local_key,
                                      const string &remote_key) override;
    void          addConnections(const AmMediaStateArgs &args) override;
    void          updateConnections(const AmMediaStateArgs &args) override;
    const char   *state2str() override;
};

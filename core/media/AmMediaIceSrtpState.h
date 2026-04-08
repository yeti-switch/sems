#pragma once

#include "AmMediaIceState.h"
#include "AmMediaSrtpState.h"

class AmMediaIceSrtpState : public AmMediaIceState, public AmMediaSrtpState {
  public:
    AmMediaIceSrtpState(AmMediaTransport *transport);
    AmMediaState *init(const AmMediaStateArgs &args) override;
    AmMediaState *initSrtp(AmStreamConnection::ConnectionType base_conn_type) override;
    AmMediaState *update(const AmMediaStateArgs &args) override;
    AmMediaState *onSrtpKeysAvailable(uint8_t transport_type, uint16_t srtp_profile, const string &local_key,
                                      const string &remote_key) override;
    void          updateConnections(const AmMediaStateArgs &args) override;
    const char   *state2str() override;

  protected:
    AmMediaState *nextState() override;
};

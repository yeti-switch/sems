#pragma once

#include "AmMediaState.h"
#include "AmRtpConnection.h"

class AmMediaSrtpState : public virtual AmMediaState {
  public:
    AmMediaSrtpState(AmMediaTransport *transport);
    /* dtls+srtp, zrtp+srtp; base_conn_type is dtls or zrtp */
    virtual AmMediaState *initSrtp(AmStreamConnection::ConnectionType base_conn_type);
    AmMediaState         *onSrtpKeysAvailable(uint8_t transport_type, uint16_t srtp_profile, const string &local_key,
                                              const string &remote_key) override;
    void                  addConnections(const AmMediaStateArgs &args) override;
    void                  updateConnections(const AmMediaStateArgs &args) override;
    const char           *state2str() override;
};

#pragma once

#include "AmMediaState.h"

class AmMediaDtlsState : public virtual AmMediaState {
  protected:
    bool is_dtls_srtp;

  public:
    AmMediaDtlsState(AmMediaTransport *transport);
    AmMediaState *init(const AmMediaStateArgs &args) override;
    AmMediaState *update(const AmMediaStateArgs &args) override;
    AmMediaState *onSrtpKeysAvailable() override;
    void          addConnections(const AmMediaStateArgs &args) override;
    void          updateConnections(const AmMediaStateArgs &args) override;
    bool          isDtlsSrtp() { return is_dtls_srtp; }
    const char   *state2str() override;
};

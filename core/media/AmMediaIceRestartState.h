#pragma once

#include "AmMediaIceState.h"

class AmMediaIceRestartState : public AmMediaIceState {
  public:
    AmMediaIceRestartState(AmMediaTransport *transport);
    AmMediaState *init(const AmMediaStateArgs &args) override;
    const char   *state2str() override;

  protected:
    void          removeConnections();
    AmMediaState *allowStunConnection(const sockaddr_storage *remote_addr, uint32_t priority) override;
};

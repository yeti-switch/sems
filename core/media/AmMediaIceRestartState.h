#pragma once

#include "AmMediaIceState.h"

class AmMediaIceRestartState : public AmMediaIceState {
  public:
    AmMediaIceRestartState(AmMediaTransport *transport);
    const char *state2str() override;

  protected:
    void          removeConnections();
    AmMediaState *allowStunConnection(const sockaddr_storage *remote_addr, uint32_t priority) override;
};

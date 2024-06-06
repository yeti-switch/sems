#pragma once

#include "AmMediaIceState.h"

class AmMediaIceRestartState
  : public AmMediaIceState
{
public:
    AmMediaIceRestartState(AmMediaTransport *transport);
    AmMediaState* allowStunConnection(sockaddr_storage* remote_addr, uint32_t priority) override;
    const char* state2str() override;

protected:
    void removeConnections();
};

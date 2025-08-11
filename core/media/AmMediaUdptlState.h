#pragma once

#include "AmMediaState.h"

class AmMediaUdptlState : virtual public AmMediaState {
  public:
    AmMediaUdptlState(AmMediaTransport *transport);
    AmMediaState *init(const AmMediaStateArgs &args) override;
    void          addConnections(const AmMediaStateArgs &args) override;
    const char   *state2str() override;
};

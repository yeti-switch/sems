#include "AmMediaState.h"

AmMediaState::AmMediaState(AmMediaTransport* transport)
  : transport(transport)
{
}

AmMediaState::~AmMediaState()
{
}

const char* AmMediaState::state2str()
{
    static const char *state = "NONE";
    return state;
}

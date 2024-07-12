#include "AmMediaState.h"

AmMediaState::AmMediaState(AmMediaTransport* transport)
  : transport(transport)
{
}

AmMediaState* AmMediaState::init(const AmMediaStateArgs& args)
{
    addConnections(args);
    return this;
}

AmMediaState* AmMediaState::update(const AmMediaStateArgs& args)
{
    updateConnections(args);
    return this;
}

const char* AmMediaState::state2str()
{
    static const char *state = "NONE";
    return state;
}

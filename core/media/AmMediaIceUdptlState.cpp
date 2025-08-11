#include "AmMediaIceUdptlState.h"
#include "AmMediaState.h"
#include "AmMediaTransport.h"

AmMediaIceUdptlState::AmMediaIceUdptlState(AmMediaTransport *transport)
    : AmMediaState(transport)
    , AmMediaIceState(transport)
    , AmMediaUdptlState(transport)
{
}

AmMediaState *AmMediaIceUdptlState::init(const AmMediaStateArgs &args)
{
    return AmMediaUdptlState::init(args);
}

AmMediaState *AmMediaIceUdptlState::update(const AmMediaStateArgs &args)
{
    return AmMediaIceState::update(args);
}

const char *AmMediaIceUdptlState::state2str()
{
    static const char *state = "ICE-UDPTL";
    return state;
}

AmMediaState *AmMediaIceUdptlState::nextState()
{
    return this;
}

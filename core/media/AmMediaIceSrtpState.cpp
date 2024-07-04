#include "AmMediaTransport.h"
#include "AmMediaIceSrtpState.h"
#include "AmMediaState.h"

AmMediaIceSrtpState::AmMediaIceSrtpState(AmMediaTransport *transport)
  : AmMediaState(transport), AmMediaIceState(transport), AmMediaSrtpState(transport)
{
}

AmMediaState* AmMediaIceSrtpState::init(const AmMediaStateArgs& args)
{
    return AmMediaSrtpState::init(args);
}

AmMediaState* AmMediaIceSrtpState::update(const AmMediaStateArgs& args)
{
    return AmMediaIceState::update(args);
}

AmMediaState* AmMediaIceSrtpState::onSrtpKeysAvailable()
{
    return this;
}

AmMediaState* AmMediaIceSrtpState::nextState()
{
    return this;
}

const char* AmMediaIceSrtpState::state2str()
{
    static const char *state = "ICE-SRTP";
    return state;
}

#include "AmMediaTransport.h"
#include "AmMediaIceRtpState.h"

AmMediaIceRtpState::AmMediaIceRtpState(AmMediaTransport *transport)
    : AmMediaState(transport)
    , AmMediaIceState(transport)
    , AmMediaRtpState(transport)
{
}

AmMediaState *AmMediaIceRtpState::init(const AmMediaStateArgs &args)
{
    return AmMediaRtpState::init(args);
}

AmMediaState *AmMediaIceRtpState::update(const AmMediaStateArgs &args)
{
    return AmMediaIceState::update(args);
}

AmMediaState *AmMediaIceRtpState::nextState()
{
    return this;
}

const char *AmMediaIceRtpState::state2str()
{
    static const char *state = "ICE-RTP";
    return state;
}

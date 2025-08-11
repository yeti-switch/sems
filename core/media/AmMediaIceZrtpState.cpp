#include "AmMediaTransport.h"
#include "AmMediaIceZrtpState.h"
#include "AmMediaIceSrtpState.h"

AmMediaIceZrtpState::AmMediaIceZrtpState(AmMediaTransport *transport)
    : AmMediaState(transport)
    , AmMediaSrtpState(transport)
    , AmMediaIceState(transport)
    , AmMediaZrtpState(transport)
{
}

AmMediaState *AmMediaIceZrtpState::init(const AmMediaStateArgs &args)
{
    return AmMediaZrtpState::init(args);
}

AmMediaState *AmMediaIceZrtpState::update(const AmMediaStateArgs &args)
{
    return AmMediaIceState::update(args);
}

AmMediaState *AmMediaIceZrtpState::onSrtpKeysAvailable()
{
    auto ice_srtp_state = new AmMediaIceSrtpState(transport);
    return ice_srtp_state->initSrtp(AmStreamConnection::ZRTP_CONN);
}

AmMediaState *AmMediaIceZrtpState::nextState()
{
    return this;
}

const char *AmMediaIceZrtpState::state2str()
{
    static const char *state = "ICE-ZRTP";
    return state;
}

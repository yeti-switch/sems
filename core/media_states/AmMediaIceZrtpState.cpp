#include "AmMediaIceZrtpState.h"
#include "AmMediaIceSrtpState.h"

AmMediaIceZrtpState::AmMediaIceZrtpState(AmMediaTransport *transport)
  : AmMediaState(transport), AmMediaSrtpState(transport), AmMediaIceState(transport), AmMediaZrtpState(transport)
{
}

AmMediaState* AmMediaIceZrtpState::init(const AmArg& args)
{
    return AmMediaZrtpState::init(args);
}

AmMediaState* AmMediaIceZrtpState::update(const AmArg& args)
{
    return AmMediaIceState::update(args);
}

AmMediaState* AmMediaIceZrtpState::allowStunConnection(sockaddr_storage* remote_addr, uint32_t priority)
{
    transport->storeAllowedIceAddr(remote_addr, priority);
    resetCurRtpConnection();
    return this;
}

AmMediaState* AmMediaIceZrtpState::onSrtpKeysAvailable()
{
    auto ice_srtp_state = new AmMediaIceSrtpState(transport);
    return ice_srtp_state->initSrtp(AmStreamConnection::ZRTP_CONN);
}

const char* AmMediaIceZrtpState::state2str()
{
    static const char *state = "ICE-ZRTP";
    return state;
}

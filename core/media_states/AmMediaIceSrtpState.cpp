#include "AmMediaIceSrtpState.h"
#include "AmMediaState.h"

AmMediaIceSrtpState::AmMediaIceSrtpState(AmMediaTransport *transport)
  : AmMediaState(transport), AmMediaIceState(transport), AmMediaSrtpState(transport)
{
}

AmMediaState* AmMediaIceSrtpState::init(const AmArg& args)
{
    return AmMediaSrtpState::init(args);
}

AmMediaState* AmMediaIceSrtpState::update(const AmArg& args)
{
    return AmMediaIceState::update(args);
}

AmMediaState* AmMediaIceSrtpState::allowStunConnection(sockaddr_storage* remote_addr, uint32_t priority)
{
    transport->storeAllowedIceAddr(remote_addr, priority);
    resetCurRtpConnection();
    return this;
}

AmMediaState* AmMediaIceSrtpState::onSrtpKeysAvailable()
{
    return this;
}

const char* AmMediaIceSrtpState::state2str()
{
    static const char *state = "ICE-SRTP";
    return state;
}

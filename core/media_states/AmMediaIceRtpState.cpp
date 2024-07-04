#include "AmMediaTransport.h"
#include "AmMediaIceRtpState.h"

AmMediaIceRtpState::AmMediaIceRtpState(AmMediaTransport *transport)
  : AmMediaState(transport), AmMediaIceState(transport), AmMediaRtpState(transport)
{
}

AmMediaState* AmMediaIceRtpState::init(const AmArg& args)
{
    return AmMediaRtpState::init(args);
}

AmMediaState* AmMediaIceRtpState::update(const AmArg& args)
{
    return AmMediaIceState::update(args);
}

AmMediaState* AmMediaIceRtpState::allowStunConnection(sockaddr_storage* remote_addr, uint32_t priority)
{
    transport->storeAllowedIceAddr(remote_addr, priority);
    resetCurRtpConnection();
    return this;
}

const char* AmMediaIceRtpState::state2str()
{
    static const char *state = "ICE-RTP";
    return state;
}

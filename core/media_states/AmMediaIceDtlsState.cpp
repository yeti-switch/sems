#include "AmMediaIceDtlsState.h"
#include "AmMediaIceSrtpState.h"
#include "AmMediaState.h"

AmMediaIceDtlsState::AmMediaIceDtlsState(AmMediaTransport *transport)
  : AmMediaState(transport), AmMediaIceState(transport), AmMediaDtlsState(transport)
{
}

AmMediaState* AmMediaIceDtlsState::init(const AmArg& args)
{
    return AmMediaDtlsState::init(args);
}

AmMediaState* AmMediaIceDtlsState::update(const AmArg& args)
{
    return AmMediaIceState::update(args);
}

AmMediaState* AmMediaIceDtlsState::allowStunConnection(sockaddr_storage* remote_addr, uint32_t priority)
{
    transport->storeAllowedIceAddr(remote_addr, priority);
    resetCurRtpConnection();
    return this;
}

AmMediaState* AmMediaIceDtlsState::onSrtpKeysAvailable()
{
    if(is_dtls_srtp) {
        auto ice_srtp_state = new AmMediaIceSrtpState(transport);
        return ice_srtp_state->initSrtp(AmStreamConnection::DTLS_CONN);
    }

    return nullptr;
}

const char* AmMediaIceDtlsState::state2str()
{
    static const char *state = "ICE-DTLS";
    return state;
}

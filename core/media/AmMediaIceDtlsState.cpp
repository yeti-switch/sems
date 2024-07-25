#include "AmMediaIceDtlsState.h"
#include "AmMediaIceSrtpState.h"
#include "AmMediaState.h"
#include "AmMediaTransport.h"

AmMediaIceDtlsState::AmMediaIceDtlsState(AmMediaTransport *transport)
  : AmMediaState(transport), AmMediaIceState(transport), AmMediaDtlsState(transport)
{
}

AmMediaState* AmMediaIceDtlsState::init(const AmMediaStateArgs& args)
{
    return AmMediaDtlsState::init(args);
}

AmMediaState* AmMediaIceDtlsState::update(const AmMediaStateArgs& args)
{
    return AmMediaIceState::update(args);
}

AmMediaState* AmMediaIceDtlsState::onSrtpKeysAvailable()
{
    if(is_dtls_srtp) {
        auto ice_srtp_state = new AmMediaIceSrtpState(transport);
        return ice_srtp_state->initSrtp(AmStreamConnection::DTLS_CONN);
    }

    return nullptr;
}

AmMediaState* AmMediaIceDtlsState::nextState()
{
    return this;
}

const char* AmMediaIceDtlsState::state2str()
{
    static const char *state = "ICE-DTLS";
    return state;
}
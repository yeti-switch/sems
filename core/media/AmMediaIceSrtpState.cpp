#include "AmMediaTransport.h"
#include "AmMediaIceSrtpState.h"
#include "AmMediaState.h"

AmMediaIceSrtpState::AmMediaIceSrtpState(AmMediaTransport *transport)
    : AmMediaState(transport)
    , AmMediaIceState(transport)
    , AmMediaSrtpState(transport)
{
}

AmMediaState *AmMediaIceSrtpState::init(const AmMediaStateArgs &args)
{
    return AmMediaSrtpState::init(args);
}

AmMediaState *AmMediaIceSrtpState::initSrtp(AmStreamConnection::ConnectionType base_conn_type)
{
    AmMediaSrtpState::initSrtp(base_conn_type);
    resetCurRtpConnection();
    return this;
}

AmMediaState *AmMediaIceSrtpState::update(const AmMediaStateArgs &args)
{
    updateConnections(args);
    return AmMediaIceState::update(args);
}

void AmMediaIceSrtpState::updateConnections(const AmMediaStateArgs &args)
{
    transport->findCurRtpConn([&](auto conn) {
        if (AmSrtpConnection *srtp_conn = dynamic_cast<AmSrtpConnection *>(conn)) {
            auto &cred = this->transport->getConnFactory()->srtp_cred;
            srtp_conn->update_keys(cred.srtp_profile, cred.local_key, cred.remote_keys);
        }
    });

    transport->findCurRtcpConn([&](auto conn) {
        if (AmSrtpConnection *srtp_conn = dynamic_cast<AmSrtpConnection *>(conn)) {
            auto &cred = this->transport->getConnFactory()->srtp_cred;
            srtp_conn->update_keys(cred.srtp_profile, cred.local_key, cred.remote_keys);
        }
    });
}

AmMediaState *AmMediaIceSrtpState::onSrtpKeysAvailable()
{
    return this;
}

AmMediaState *AmMediaIceSrtpState::nextState()
{
    return this;
}

const char *AmMediaIceSrtpState::state2str()
{
    static const char *state = "ICE-SRTP";
    return state;
}

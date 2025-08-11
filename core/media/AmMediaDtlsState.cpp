#include "AmMediaDtlsState.h"
#include "AmRtpStream.h"
#include "AmMediaSrtpState.h"
#include "AmMediaSecureUdptlState.h"

AmMediaDtlsState::AmMediaDtlsState(AmMediaTransport *transport)
    : AmMediaState(transport)
    , is_dtls_srtp(false)
{
}

AmMediaState *AmMediaDtlsState::init(const AmMediaStateArgs &args)
{
    is_dtls_srtp = args.dtls_srtp.value_or(false);
    return AmMediaState::init(args);
}

AmMediaState *AmMediaDtlsState::update(const AmMediaStateArgs &args)
{
    is_dtls_srtp = args.dtls_srtp.value_or(false);
    return AmMediaState::update(args);
}

void AmMediaDtlsState::addConnections(const AmMediaStateArgs &args)
{
    if (!args.address || !args.port || !args.family)
        return;
    if (*args.family != transport->getLocalAddrFamily())
        return;

    // check is dtls connection already exists
    auto pred = [&](auto conn) {
        return conn->getConnType() == AmStreamConnection::DTLS_CONN && conn->getRHost() == *args.address &&
               conn->getRPort() == *args.port;
    };
    if (transport->getConnection(pred))
        return;

    auto dtls_context = transport->getRtpStream()->getDtlsContext(transport->getTransportType());
    if (!dtls_context)
        return;
    CLASS_DBG("add dtls connection, state:%s, type:%s, raddr:%s, rport:%d", state2str(), transport->type2str(),
              args.address.value().c_str(), *args.port);
    transport->addConnection(
        transport->getConnFactory()->createDtlsConnection(*args.address, *args.port, dtls_context));
}

void AmMediaDtlsState::updateConnections(const AmMediaStateArgs &args)
{
    if (!args.address || !args.port)
        return;
    CLASS_DBG("update DTLS connection endpoint");
    transport->iterateConnections(
        { AmStreamConnection::DTLS_CONN, AmStreamConnection::RTP_CONN, AmStreamConnection::RTCP_CONN },
        [&](auto conn, bool &stop) { conn->setRAddr(*args.address, *args.port); });
}

AmMediaState *AmMediaDtlsState::onSrtpKeysAvailable()
{
    if (is_dtls_srtp) {
        auto srtp_state = new AmMediaSrtpState(transport);
        return srtp_state->initSrtp(AmStreamConnection::DTLS_CONN);
    } else {
        // if not dtls+srtp consider as dtls+udptl
        auto             sec_udpt_state = new AmMediaSecureUdptlState(transport);
        AmMediaStateArgs args;
        args.family = transport->getLocalAddrFamily();
        sec_udpt_state->init(args);
        return sec_udpt_state;
    }
}

const char *AmMediaDtlsState::state2str()
{
    static const char *state = "DTLS";
    return state;
}

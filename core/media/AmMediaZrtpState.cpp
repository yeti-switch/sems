#include "AmMediaZrtpState.h"
#include "AmMediaState.h"
#include "AmRtpStream.h"

AmMediaZrtpState::AmMediaZrtpState(AmMediaTransport *transport)
  : AmMediaState(transport), AmMediaSrtpState(transport)
{
}

AmMediaState* AmMediaZrtpState::init(const AmMediaStateArgs& args)
{
    addConnections(args);
    transport->getRtpStream()->initZrtp();
    return this;
}

AmMediaState* AmMediaZrtpState::update(const AmMediaStateArgs& args)
{
    updateConnections(args);
    transport->getRtpStream()->initZrtp();
    return this;
}

void AmMediaZrtpState::addConnections(const AmMediaStateArgs& args)
{
    if(!args.address || !args.port) return;

    try {
        CLASS_DBG("add zrtp connection, state:%s, type:%s, remote_address:%s, remote_port:%d",
                  state2str(), transport->type2str(), args.address.value().c_str(), *args.port);
        auto new_zrtp_conn = transport->getConnFactory()->createZrtpConnection(
            *args.address, *args.port, transport->getRtpStream()->getZrtpContext());
        transport->addConnection(new_zrtp_conn, [&]() {
            transport->setCurRtpConn(new_zrtp_conn);
        });

        CLASS_DBG("add rtcp connection, state:%s, type:%s, remote_address:%s, remote_port:%d",
                  state2str(), transport->type2str(), args.address.value().c_str(), *args.port);
        auto new_rtcp_conn = transport->getConnFactory()->createRtcpConnection(*args.address, *args.port);
        transport->addConnection(new_rtcp_conn, [&]() {
            transport->setCurRtcpConn(new_rtcp_conn);
        });
    } catch(string& error) {
        CLASS_ERROR("ZRTP connection error: %s", error.c_str());
    }
}

void AmMediaZrtpState::updateConnections(const AmMediaStateArgs& args)
{
    if(!args.address || !args.port) return;

    try {
        transport->findCurRtpConn([&](auto conn) {
            CLASS_DBG("update ZRTP connection endpoint");
            conn->setRAddr(*args.address, *args.port);
        });
    } catch(string& error) {
        CLASS_ERROR("ZRTP connection error: %s", error.c_str());
    }
}

AmMediaState* AmMediaZrtpState::onSrtpKeysAvailable()
{
    transport->removeCurRtcpConn();

    auto srtp_state = new AmMediaSrtpState(transport);
    return srtp_state->initSrtp(AmStreamConnection::ZRTP_CONN);
}

const char* AmMediaZrtpState::state2str()
{
    static const char *state = "ZRTP";
    return state;
}

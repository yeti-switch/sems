#include "AmMediaZrtpState.h"
#include "AmMediaState.h"
#include "AmRtpStream.h"

AmMediaZrtpState::AmMediaZrtpState(AmMediaTransport *transport)
  : AmMediaState(transport), AmMediaSrtpState(transport)
{
}

AmMediaState* AmMediaZrtpState::init(const AmArg& args)
{
    string address = args["address"].asCStr();
    int port = args["port"].asInt();

    try {
        CLASS_DBG("add zrtp connection, state:%s, type:%s, remote_address:%s, remote_port:%d",
                  state2str(), transport->type2str(), address.c_str(), port);
        auto new_zrtp_conn = transport->getConnFactory()->createZrtpConnection(address, port, transport->getRtpStream()->getZrtpContext());
        transport->addConnection(new_zrtp_conn, [&]() {
            transport->setCurRtpConn(new_zrtp_conn);
        });

        CLASS_DBG("add rtcp connection, state:%s, type:%s, remote_address:%s, remote_port:%d",
                  state2str(), transport->type2str(), address.c_str(), port);
        auto new_rtcp_conn = transport->getConnFactory()->createRtcpConnection(address, port);
        transport->addConnection(new_rtcp_conn, [&]() {
            transport->setCurRtcpConn(new_rtcp_conn);
        });
    } catch(string& error) {
        CLASS_ERROR("ZRTP connection error: %s", error.c_str());
    }

    transport->getRtpStream()->initZrtp();
    return this;
}

AmMediaState* AmMediaZrtpState::update(const AmArg& args)
{
    string address = args["address"].asCStr();
    int port = args["port"].asInt();

    try {
        transport->findCurRtpConn([&](auto conn) {
            CLASS_DBG("update ZRTP connection endpoint");
            conn->setRAddr(address, port);
        });
    } catch(string& error) {
        CLASS_ERROR("ZRTP connection error: %s", error.c_str());
    }

    transport->getRtpStream()->initZrtp();
    return this;
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

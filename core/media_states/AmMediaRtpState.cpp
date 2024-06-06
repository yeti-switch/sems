#include "AmMediaRtpState.h"

AmMediaRtpState::AmMediaRtpState(AmMediaTransport *transport)
  : AmMediaState(transport)
{
}

AmMediaState* AmMediaRtpState::init(const AmArg& args)
{
    string address = args["address"].asCStr();
    int port = args["port"].asInt();

    if(transport->getTransportType() == RTP_TRANSPORT) {
        CLASS_DBG("add rtp connection, state:%s, type:%s, raddr:%s, rport:%d",
            state2str(), transport->type2str(), address.c_str(), port);
        transport->addConnection(
            transport->getConnFactory()->createRtpConnection(address, port));
    }

    CLASS_DBG("add rtcp connection, state:%s, type:%s, raddr:%s, rport:%d",
        state2str(), transport->type2str(), address.c_str(), port);
    transport->addConnection(
        transport->getConnFactory()->createRtcpConnection(address, port));

    return this;
}

AmMediaState* AmMediaRtpState::update(const AmArg& args)
{
    string address = args["address"].asCStr();
    int port = args["port"].asInt();

    if(transport->getCurRtpConn()) {
        transport->findCurRtpConn([&](auto conn) {
            CLASS_DBG("setRAddr for cur_rtp_conn %p", conn);
            conn->setRAddr(address, port);
        });
    } else {
        CLASS_DBG("setRAddr for all RTP connections");
        transport->iterateConnections(AmStreamConnection::RTP_CONN, [&](auto conn, bool& stop) {
            conn->setRAddr(address, port);
        });
    }

    if(transport->getCurRtcpConn()) {
        transport->findCurRtcpConn([&](auto conn) {
            CLASS_DBG("setRAddr for cur_rtcp_conn %p", conn);
            conn->setRAddr(address, port);
        });
    } else {
        CLASS_DBG("setRAddr for all RTCP connections");
        transport->iterateConnections(AmStreamConnection::RTCP_CONN, [&](auto conn, bool& stop) {
            conn->setRAddr(address, port);
        });
    }

    if(transport->getCurRawConn()) {
        transport->getCurRawConn()->setRAddr(address, port);
    }

    return this;
}

const char* AmMediaRtpState::state2str()
{
    static const char *state = "RTP";
    return state;
}

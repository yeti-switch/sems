#include "AmMediaTransport.h"
#include "AmMediaRtpState.h"

AmMediaRtpState::AmMediaRtpState(AmMediaTransport *transport)
  : AmMediaState(transport)
{
}

void AmMediaRtpState::addConnections(const AmMediaStateArgs& args)
{
    if(!args.address || !args.port || !args.family) return;
    if(args.family.value() != transport->getLocalAddrFamily()) return;

    // check is rtp connection already exists
    auto pred = [&](auto conn) {
        return conn->getConnType() == AmStreamConnection::RTP_CONN &&
                conn->getRHost() == *args.address &&
                conn->getRPort() == *args.port;
    };
    if(transport->getConnection(pred)) return;

    if(transport->getTransportType() == RTP_TRANSPORT) {
        CLASS_DBG("add rtp connection, state:%s, type:%s, raddr:%s, rport:%d",
            state2str(), transport->type2str(), args.address.value().c_str(), *args.port);
        transport->addConnection(
            transport->getConnFactory()->createRtpConnection(*args.address, *args.port));
    }

    CLASS_DBG("add rtcp connection, state:%s, type:%s, raddr:%s, rport:%d",
        state2str(), transport->type2str(), args.address.value().c_str(), *args.port);
    transport->addConnection(
        transport->getConnFactory()->createRtcpConnection(*args.address, *args.port));
}

void AmMediaRtpState::updateConnections(const AmMediaStateArgs& args)
{
    if(!args.address || !args.port) return;

    if(transport->getCurRtpConn()) {
        transport->findCurRtpConn([&](auto conn) {
            CLASS_DBG("setRAddr for cur_rtp_conn %p", conn);
            conn->setRAddr(*args.address, *args.port);
        });
    } else {
        CLASS_DBG("setRAddr for all RTP connections");
        transport->iterateConnections(AmStreamConnection::RTP_CONN, [&](auto conn, bool& stop) {
            conn->setRAddr(*args.address, *args.port);
        });
    }

    if(transport->getCurRtcpConn()) {
        transport->findCurRtcpConn([&](auto conn) {
            CLASS_DBG("setRAddr for cur_rtcp_conn %p", conn);
            conn->setRAddr(*args.address, *args.port);
        });
    } else {
        CLASS_DBG("setRAddr for all RTCP connections");
        transport->iterateConnections(AmStreamConnection::RTCP_CONN, [&](auto conn, bool& stop) {
            conn->setRAddr(*args.address, *args.port);
        });
    }

    if(transport->getCurRawConn()) {
        transport->getCurRawConn()->setRAddr(*args.address, *args.port);
    }
}

const char* AmMediaRtpState::state2str()
{
    static const char *state = "RTP";
    return state;
}

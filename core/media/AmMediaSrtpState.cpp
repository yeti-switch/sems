#include "AmMediaTransport.h"
#include "AmMediaSrtpState.h"

AmMediaSrtpState::AmMediaSrtpState(AmMediaTransport *transport)
  : AmMediaState(transport)
{
}

void AmMediaSrtpState::addConnections(const AmMediaStateArgs& args)
{
    if(!args.address || !args.port) return;

    if(transport->getTransportType() == RTP_TRANSPORT) {
        CLASS_DBG("add srtp connection, state:%s, type:%s, raddr:%s, rport:%d",
            state2str(), transport->type2str(), args.address.value().c_str(), *args.port);
        transport->addConnection(
            transport->getConnFactory()->createSrtpConnection(*args.address, *args.port),
            [&](){ transport->setCurRtpConn(0); /* it's need for zrtp media connection establishing*/ }
        );
    }

    CLASS_DBG("add srtcp connection, state:%s, type:%s, raddr:%s, rport:%d",
        state2str(), transport->type2str(), args.address.value().c_str(), *args.port);
    transport->addConnection(
        transport->getConnFactory()->createSrtcpConnection(*args.address, *args.port),
        [&](){ transport->setCurRtcpConn(0); }
    );
}

void AmMediaSrtpState::updateConnections(const AmMediaStateArgs& args)
{
    if(!args.address || !args.port) return;

    transport->findCurRtpConn([&](auto conn) {
        CLASS_DBG("update SRTP connection endpoint");
        conn->setRAddr(*args.address, *args.port);

        if(AmSrtpConnection* srtp_conn = dynamic_cast<AmSrtpConnection *>(conn)) {
            auto & cred = this->transport->getConnFactory()->srtp_cred;
            srtp_conn->update_keys(cred.srtp_profile, cred.local_key, cred.remote_keys);
        }
    });

    transport->findCurRtcpConn([&](auto conn) {
        CLASS_DBG("update SRTCP connection endpoint");
        conn->setRAddr(*args.address, *args.port);

        if(AmSrtpConnection* srtp_conn = dynamic_cast<AmSrtpConnection *>(conn)) {
            auto & cred = this->transport->getConnFactory()->srtp_cred;
            srtp_conn->update_keys(cred.srtp_profile, cred.local_key, cred.remote_keys);
        }
    });

    transport->findCurRawConn([&](auto conn) {
        conn->setRAddr(*args.address, *args.port);
    });
}

AmMediaState* AmMediaSrtpState::initSrtp(AmStreamConnection::ConnectionType base_conn_type)
{
    vector<AmStreamConnection *> new_conns;
    transport->iterateConnections(base_conn_type, [&](auto conn, bool& stop) {
        sockaddr_storage addr;
        conn->getRAddr(&addr);
        string raddr = am_inet_ntop(&addr);
        int rport = am_get_port(&addr);

        if(transport->getTransportType() == RTP_TRANSPORT) {
            CLASS_DBG("add srtp connection, state:%s, type:%s, raddr:%s, rport:%d",
                state2str(), transport->type2str(), raddr.c_str(), rport);
            new_conns.push_back(
                transport->getConnFactory()->createSrtpConnection(raddr, rport));
        }

        CLASS_DBG("add srtcp connection, state:%s, type:%s, raddr:%s, rport:%d",
            state2str(), transport->type2str(), raddr.c_str(), rport);
        new_conns.push_back(
            transport->getConnFactory()->createSrtcpConnection(raddr, rport));
    });

    transport->addConnections(new_conns, [&](){
        transport->setCurRtpConn(0); // it's need for zrtp media connection establishing
        transport->setCurRtcpConn(0);
    });

    return this;
}

const char* AmMediaSrtpState::state2str()
{
    static const char *state = "SRTP";
    return state;
}

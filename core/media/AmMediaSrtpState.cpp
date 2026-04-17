#include "AmMediaTransport.h"
#include "AmMediaSrtpState.h"
#include "AmMediaSecureUdptlState.h"

AmMediaSrtpState::AmMediaSrtpState(AmMediaTransport *transport)
    : AmMediaState(transport)
{
}

void AmMediaSrtpState::addConnections(const AmMediaStateArgs &args)
{
    if (!args.address || !args.port || !args.family)
        return;
    if (*args.family != transport->getLocalAddrFamily())
        return;

    // check is srtp connection already exists
    auto pred = [&](auto conn) {
        int conn_type = 0;
        if (transport->getTransportType() == RTP_TRANSPORT)
            conn_type = AmStreamConnection::RTP_CONN;
        else
            conn_type = AmStreamConnection::RTCP_CONN;
        return conn->getConnType() == conn_type && conn->getRHost() == *args.address && conn->getRPort() == *args.port;
    };
    if (transport->getConnection(pred))
        return;

    if (transport->getTransportType() == RTP_TRANSPORT) {
        CLASS_DBG("add srtp connection, state:%s, type:%s, raddr:%s, rport:%d", state2str(), transport->type2str(),
                  args.address.value().c_str(), *args.port);
        transport->addConnection(transport->getConnFactory()->createSrtpConnection(*args.address, *args.port), [&]() {
            transport->setCurRtpConn(0); /* it's need for zrtp media connection establishing*/
        });
    }

    CLASS_DBG("add srtcp connection, state:%s, type:%s, raddr:%s, rport:%d", state2str(), transport->type2str(),
              args.address.value().c_str(), *args.port);
    transport->addConnection(transport->getConnFactory()->createSrtcpConnection(*args.address, *args.port),
                             [&]() { transport->setCurRtcpConn(0); });
}

void AmMediaSrtpState::updateConnections(const AmMediaStateArgs &args)
{
    if (!args.address || !args.port)
        return;

    transport->findCurRtpConn([&](auto conn) {
        CLASS_DBG("update SRTP connection endpoint");
        conn->setRAddr(*args.address, *args.port);

        if (AmSrtpConnection *srtp_conn = dynamic_cast<AmSrtpConnection *>(conn)) {
            auto &cred = this->transport->getConnFactory()->srtp_cred;
            srtp_conn->update_keys(cred.srtp_profile, cred.local_key, cred.remote_keys);
        }
    });

    transport->findCurRtcpConn([&](auto conn) {
        CLASS_DBG("update SRTCP connection endpoint");
        conn->setRAddr(*args.address, *args.port);

        if (AmSrtpConnection *srtp_conn = dynamic_cast<AmSrtpConnection *>(conn)) {
            auto &cred = this->transport->getConnFactory()->srtp_cred;
            srtp_conn->update_keys(cred.srtp_profile, cred.local_key, cred.remote_keys);
        }
    });

    transport->findCurRawConn([&](auto conn) { conn->setRAddr(*args.address, *args.port); });
}

AmMediaState *AmMediaSrtpState::initSrtp(AmStreamConnection::ConnectionType base_conn_type)
{
    vector<AmStreamConnection *> new_conns;
    transport->iterateConnections(base_conn_type, [&](auto conn, bool &stop) {
        sockaddr_storage addr;
        conn->getRAddr(&addr);
        string raddr = am_inet_ntop(&addr);
        int    rport = am_get_port(&addr);

        if (transport->getTransportType() == RTP_TRANSPORT) {
            CLASS_DBG("add srtp connection, state:%s, type:%s, raddr:%s, rport:%d", state2str(), transport->type2str(),
                      raddr.c_str(), rport);
            new_conns.push_back(transport->getConnFactory()->createSrtpConnection(raddr, rport));
        }

        CLASS_DBG("add srtcp connection, state:%s, type:%s, raddr:%s, rport:%d", state2str(), transport->type2str(),
                  raddr.c_str(), rport);
        new_conns.push_back(transport->getConnFactory()->createSrtcpConnection(raddr, rport));
    });

    transport->addConnections(new_conns, [&]() {
        transport->setCurRtpConn(0); // it's need for zrtp media connection establishing
        transport->setCurRtcpConn(0);
    });

    return this;
}

AmMediaState *AmMediaSrtpState::update(const AmMediaStateArgs &args)
{
    if (args.dtls_srtp.has_value() && !args.dtls_srtp.value()) {
        auto sec = new AmMediaSecureUdptlState(transport);
        return sec->init(args);
    }
    return AmMediaState::update(args);
}

AmMediaState *AmMediaSrtpState::onSrtpKeysAvailable(uint8_t transport_type, uint16_t srtp_profile,
                                                    const string &local_key, const string &remote_key)
{
    if (transport_type != transport->getTransportType())
        return this;

    transport->getConnFactory()->store_srtp_cred(srtp_profile, local_key, remote_key);

    auto &cred = transport->getConnFactory()->srtp_cred;

    transport->findCurRtpConn([&](auto conn) {
        if (AmSrtpConnection *srtp_conn = dynamic_cast<AmSrtpConnection *>(conn)) {
            CLASS_DBG("update SRTP keys, state:%s, type:%s", state2str(), transport->type2str());
            srtp_conn->update_keys(cred.srtp_profile, cred.local_key, cred.remote_keys);
        }
    });

    transport->findCurRtcpConn([&](auto conn) {
        if (AmSrtpConnection *srtp_conn = dynamic_cast<AmSrtpConnection *>(conn)) {
            CLASS_DBG("update SRTCP keys, state:%s, type:%s", state2str(), transport->type2str());
            srtp_conn->update_keys(cred.srtp_profile, cred.local_key, cred.remote_keys);
        }
    });

    return this;
}

const char *AmMediaSrtpState::state2str()
{
    static const char *state = "SRTP";
    return state;
}

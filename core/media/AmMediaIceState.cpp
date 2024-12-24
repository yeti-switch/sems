#include "AmMediaIceState.h"
#include "AmRtpStream.h"
#include "AmMediaIceDtlsState.h"
#include "AmMediaIceSrtpState.h"
#include "AmMediaIceZrtpState.h"
#include "AmMediaIceRtpState.h"
#include "AmMediaIceRestartState.h"

AmMediaIceState::AmMediaIceState(AmMediaTransport *transport)
  : AmMediaState(transport)
{
}

AmMediaState* AmMediaIceState::init(const AmMediaStateArgs& args)
{
    removeStunConnections();

    if(args.candidates && args.sdp_offer_owner)
        addStunConnections(*args.candidates, *args.sdp_offer_owner);

    return this;
}

AmMediaState* AmMediaIceState::update(const AmMediaStateArgs& args)
{
    if(args.need_restart.value_or(false)) {
        auto next_state = new AmMediaIceRestartState(transport);
        next_state->init(args);
        return next_state;
    }

    if(args.candidates && args.sdp_offer_owner)
        addStunConnections(*args.candidates, *args.sdp_offer_owner);

    return this;
}

bool AmMediaIceState::candidate_address_is_allowed(const string& addr_str)
{
    sockaddr_storage addr;

    if(AmConfig.ice_candidate_acl.empty())
        return true;

    if(resolver::instance()->str2ip(addr_str.data(), &addr, (address_type)(IPv4 | IPv6)) != 1) {
        /* allow FQDNs
         * TODO: create special ACL entry for FQDNs
         *  OR add option to force resolving before ACL checking */
        return true;
    }

    for(const auto& acl : AmConfig.ice_candidate_acl) {
        if(auto ret = acl.match(addr); ret.has_value()) {
            //see: AmLcConfig ice_candidate_allow, ice_candidate_deny
            return ret.value()[0];
        }
    }

    //allow if no any allow,deny actions matched
    return true;
}

void AmMediaIceState::addStunConnections(const vector<SdpIceCandidate>* candidates, bool sdp_offer_owner)
{
    if(!candidates) return;

    CLASS_DBG("addStunConnections state:%s, type:%s", state2str(), transport->type2str());

    for(auto candidate : *candidates) {
        if(candidate.transport != ICTR_UDP)
            continue;

        string addr = candidate.conn.address;
        vector<string> addr_port = explode(addr, " ");

        if(addr_port.size() != 2) continue;
        string address = addr_port[0];
        int port = 0;
        str2int(addr_port[1], port);

        if(transport->getTransportType() != candidate.comp_id ||
           transport->getLocalAddrType() != candidate.conn.addrType)
            continue;

        // check is stun connection already exists
        auto pred = [&](auto conn) {
            return conn->getConnType() == AmStreamConnection::STUN_CONN &&
                   conn->getRHost() == address &&
                   conn->getRPort() == port;
        };
        if(transport->getConnection(pred)) continue;

        try {
            if(!candidate_address_is_allowed(address)) {
                DBG("skip candidate %s:%d by ACL", address.data(), port);
                continue;
            }

            CLASS_DBG("add stun connection, state:%s, type:%s, raddr:%s, rport:%d",
                      state2str(), transport->type2str(), address.c_str(), port);
            auto conn = (AmStunConnection *)transport->getConnFactory()->createStunConnection(
                            address, port,
                            transport->getConnFactory()->ice_cred.lpriority,
                            candidate.priority);
            transport->addConnection(conn);
        } catch(string& error) {
            CLASS_ERROR("ICE candidate STUN connection error: %s", error.c_str());
        }
    }
}

void AmMediaIceState::removeStunConnections()
{
    CLASS_DBG("removeConnections, conn_type:%s, state:%s, type:%s",
              AmStreamConnection::connType2Str(AmStreamConnection::STUN_CONN).c_str(),
              state2str(), transport->type2str());
    transport->removeConnections(AmStreamConnection::STUN_CONN);
}

AmMediaState* AmMediaIceState::allowStunConnection(const sockaddr_storage* remote_addr, uint32_t priority)
{
    const string address = am_inet_ntop(remote_addr);
    const int port = am_get_port(remote_addr);
    CLASS_DBG("allow stun connection by addr: %s, port: %d, state: %s, type: %s",
              address.c_str(), port, state2str(), transport->type2str());

    AmMediaState* next_state = nextState();
    AmMediaStateArgs args;
    args.address = address;
    args.port = port;
    args.family = remote_addr->ss_family;
    if(isDtls()) args.dtls_srtp = true;

    if(next_state != this)
        next_state->init(args);
    else
        next_state->addConnections(args);

    resetCurRtpConnection();
    return next_state;
}

AmMediaState* AmMediaIceState::allowStunPair(const sockaddr_storage* remote_addr)
{
    const string address = am_inet_ntop(remote_addr);
    const int port = am_get_port(remote_addr);
    CLASS_DBG("allow stun pair by addr: %s, port: %d, state: %s, type: %s",
              address.c_str(), port, state2str(), transport->type2str());

    resetCurRtpConnection();
    return this;
}

AmMediaState * AmMediaIceState::connectionTrafficDetected(const sockaddr_storage* remote_addr)
{
    const string address = am_inet_ntop(remote_addr);
    const int port = am_get_port(remote_addr);
    CLASS_DBG("connection trafic detected by addr: %s, port: %d, state: %s, type: %s",
              address.c_str(), port, state2str(), transport->type2str());

    resetCurRtpConnection();
    return this;
}

void AmMediaIceState::setCurrentConnection(AmStreamConnection* conn)
{
    if(transport->getTransportType() == RTP_TRANSPORT)
        transport->setCurRtpConn(conn);
    else if(transport->getTransportType() == RTCP_TRANSPORT)
        transport->setCurRtcpConn(conn);
}

void AmMediaIceState::resetCurRtpConnection() {
    setCurrentConnection(nullptr);
    auto target_addr = transport->getAllowedIceAddr();
    if(!target_addr) return;

    AmStreamConnection::ConnectionType conn_type = AmStreamConnection::RTP_CONN;
    if(transport->getTransportType() == RTCP_TRANSPORT) {
        conn_type = AmStreamConnection::RTCP_CONN;
    }

    transport->findConnection(
        [&](auto conn) { return conn->getConnType() == AmStreamConnection::ZRTP_CONN && conn->isAddrConnection(target_addr); },
        [&](auto conn) { setCurrentConnection(conn); }
    );

    if(!transport->getCurRtpConn()) {
        transport->findConnection(
            [&](auto conn) { return conn->getConnType() == conn_type && conn->isAddrConnection(target_addr); },
            [&](auto conn) { setCurrentConnection(conn); }
        );
    }

    AmStreamConnection* conn = transport->getCurRtpConn();
    if(transport->getTransportType() == RTCP_TRANSPORT)
        conn = transport->getCurRtcpConn();
    transport->setRAddr(am_inet_ntop(target_addr), am_get_port(target_addr));
    DBG("current %s connection type %s", transport->getTransportType() == RTP_TRANSPORT ? "rtp" : "rtcp",
                                         conn ? AmStreamConnection::connType2Str(conn->getConnType()).c_str() : "");
}

bool AmMediaIceState::isSrtp()
{
    return transport->getConnFactory()->srtp_cred.srtp_profile > srtp_profile_reserved;
}

bool AmMediaIceState::isDtls()
{
    return !isSrtp() && transport->getRtpStream()->getDtlsContext(transport->getTransportType());
}

bool AmMediaIceState::isZrtp()
{
#ifdef WITH_ZRTP
    return !isSrtp() &&
           !isDtls() &&
            transport->getRtpStream()->isZrtpEnabled() &&
            transport->isZrtpEnable() &&
           !transport->getRtpStream()->getZrtpContext()->getRemoteHash().empty();
#else
    return false;
#endif
}

bool AmMediaIceState::isRtp()
{
    return !isSrtp() && !isDtls() && !isZrtp();
}

AmMediaState* AmMediaIceState::nextState()
{
    if(isSrtp()) // sdes+srtp or keys alredy available via dtls or zrtp
        return new AmMediaIceSrtpState(transport);

    if(isDtls()) // dtls+srtp
        return new AmMediaIceDtlsState(transport);

#ifdef WITH_ZRTP
    if(isZrtp()) // zrtp+srtp
        return new AmMediaIceZrtpState(transport);
#endif

    return new AmMediaIceRtpState(transport); // rtp
}

const char* AmMediaIceState::state2str()
{
    static const char *state = "ICE";
    return state;
}

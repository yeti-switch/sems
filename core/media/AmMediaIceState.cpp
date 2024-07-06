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

        if(transport->getConnection(pred)){
            continue;
        }

        try {
            CLASS_DBG("add stun connection, state:%s, type:%s, raddr:%s, rport:%d",
                      state2str(), transport->type2str(), address.c_str(), port);
            auto conn = (AmStunConnection *)transport->getConnFactory()->createStunConnection(
                            address, port,
                            transport->getConnFactory()->ice_cred.lpriority,
                            candidate.priority);
            transport->addConnection(conn);
            conn->send_request();
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
    transport->removeAllowedIceAddrs();
    transport->removeConnections(AmStreamConnection::STUN_CONN);
}

AmMediaState* AmMediaIceState::allowStunConnection(const sockaddr_storage* remote_addr, uint32_t priority)
{
    transport->storeAllowedIceAddr(remote_addr, priority);

    const string address = am_inet_ntop(remote_addr);
    const int port = am_get_port(remote_addr);
    CLASS_DBG("allow stun connection by addr:%s, port:%d, state:%s, type:%s",
              address.c_str(), port, state2str(), transport->type2str());

    if(remote_addr->ss_family != transport->getLocalAddrFamily()) {
        resetCurRtpConnection();
        return this;
    }

    AmMediaState* next_state = nextState();
    AmMediaStateArgs args;
    args.address = address;
    args.port = port;
    if(isDtls()) args.dtls_srtp = true;

    if(next_state != this)
        next_state->init(args);
    else
        next_state->addConnections(args);

    resetCurRtpConnection();
    return next_state;
}

void AmMediaIceState::resetCurRtpConnection() {
    auto target_addr = transport->getAllowedIceAddr();
    if(!target_addr) return;

    transport->findConnection(
        [&](auto conn) { return conn->getConnType() == AmRawConnection::ZRTP_CONN && conn->isAddrConnection(target_addr); },
        [&](auto conn) { transport->setCurRtpConn(conn); }
    );

    if(!transport->getCurRtpConn()) {
        transport->findConnection(
            [&](auto conn) { return conn->getConnType() == AmRawConnection::RTP_CONN && conn->isAddrConnection(target_addr); },
            [&](auto conn) { transport->setCurRtpConn(conn); }
        );
    }

    transport->setRAddr(am_inet_ntop(target_addr), am_get_port(target_addr));
    DBG("current rtp connection type %s", transport->getCurRtpConn() ? AmStreamConnection::connType2Str(transport->getCurRtpConn()->getConnType()).c_str() : "");
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
#elif
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

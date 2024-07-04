#include "AmMediaIceRestartState.h"
#include "AmMediaState.h"
#include "AmMediaTransport.h"

AmMediaIceRestartState::AmMediaIceRestartState(AmMediaTransport *transport)
  : AmMediaState(transport), AmMediaIceState(transport)
{
}

AmMediaState* AmMediaIceRestartState::allowStunConnection(const sockaddr_storage* remote_addr, uint32_t priority)
{
    transport->removeAllowedIceAddrs();
    removeConnections();
    return AmMediaIceState::allowStunConnection(remote_addr, priority);
}

void AmMediaIceRestartState::removeConnections()
{
    CLASS_DBG("removeConnections, conn_type:[%s, %s, %s, %s], state:%s, type:%s",
              AmStreamConnection::connType2Str(AmStreamConnection::RTP_CONN).c_str(),
              AmStreamConnection::connType2Str(AmStreamConnection::RTCP_CONN).c_str(),
              AmStreamConnection::connType2Str(AmStreamConnection::DTLS_CONN).c_str(),
              AmStreamConnection::connType2Str(AmStreamConnection::ZRTP_CONN).c_str(),
              state2str(), transport->type2str());

    transport->removeConnections(
        {AmStreamConnection::RTP_CONN,
         AmStreamConnection::RTCP_CONN,
         AmStreamConnection::DTLS_CONN,
         AmStreamConnection::ZRTP_CONN
        }, [&](){
            transport->setCurRtpConn(0);
            transport->setCurRtcpConn(0);
        });
}

const char* AmMediaIceRestartState::state2str()
{
    static const char *state = "ICE-RESTART";
    return state;
}

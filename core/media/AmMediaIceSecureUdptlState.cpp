#include "AmMediaTransport.h"
#include "AmMediaIceSecureUdptlState.h"
#include "AmRtpStream.h"

AmMediaIceSecureUdptlState::AmMediaIceSecureUdptlState(AmMediaTransport *transport)
  : AmMediaState(transport), AmMediaIceState(transport), AmMediaSecureUdptlState(transport)
{
}

AmMediaState* AmMediaIceSecureUdptlState::init(const AmMediaStateArgs& args)
{
    if(args.address && args.port) {
        return AmMediaSecureUdptlState::init(args);
    } else {
        transport->setMode(AmMediaTransport::TRANSPORT_MODE_DTLS_FAX);
        AmMediaSecureUdptlState::addConnections(args);
    }
    return this;
}

AmMediaState * AmMediaIceSecureUdptlState::update(const AmMediaStateArgs& args)
{
    return AmMediaIceState::update(args);
}

void AmMediaIceSecureUdptlState::addConnections(const AmMediaStateArgs& args)
{
    bool exists = false;
    AmStreamConnection* dtls_conn = NULL;
    auto pred = [&](auto conn, bool& stop) {
        if(conn->getConnType() == AmStreamConnection::UDPTL_CONN &&
           conn->getRHost() == *args.address &&
           conn->getRPort() == *args.port) {
            stop = true;
            exists = true;
        } else if(conn->getConnType() == AmStreamConnection::DTLS_CONN &&
                  conn->getRHost() == *args.address &&
                  conn->getRPort() == *args.port) {
            dtls_conn = conn;
        }
    };
    transport->iterateConnections(
        {AmStreamConnection::UDPTL_CONN,
         AmStreamConnection::DTLS_CONN},
         pred);
    if(exists) return;

    vector<AmStreamConnection*> new_conns;
    auto dtls_context = transport->getRtpStream()->getDtlsContext(transport->getTransportType());
    if(!dtls_context) return;
    CLASS_DBG("add dtls connection, state:%s, type:%s, raddr:%s, rport:%d",
        state2str(), transport->type2str(), args.address.value().c_str(), *args.port);
    dtls_conn = transport->getConnFactory()->createDtlsConnection(*args.address, *args.port, dtls_context);
    new_conns.push_back(dtls_conn);
    CLASS_DBG("add dtls-udptl connection, state:%s, type:%s, raddr:%s, rport:%d",
        state2str(), transport->type2str(), args.address.value().c_str(), *args.port);
    new_conns.push_back(
        transport->getConnFactory()->createDtlsUdptlConnection(*args.address, *args.port, dtls_conn));
    transport->addConnections(new_conns);
}

const char* AmMediaIceSecureUdptlState::state2str()
{
    static const char *state = "ICE-DTLS-UDPTL";
    return state;
}

AmMediaState * AmMediaIceSecureUdptlState::nextState()
{
    return this;
}

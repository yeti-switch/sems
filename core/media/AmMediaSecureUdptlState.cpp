#include "AmMediaTransport.h"
#include "AmMediaSecureUdptlState.h"

AmMediaSecureUdptlState::AmMediaSecureUdptlState(AmMediaTransport *transport)
  : AmMediaState(transport)
{
}

AmMediaState* AmMediaSecureUdptlState::init(const AmMediaStateArgs& args)
{
    transport->setMode(AmMediaTransport::TRANSPORT_MODE_DTLS_FAX);
    return AmMediaState::init(args);
}

void AmMediaSecureUdptlState::addConnections(const AmMediaStateArgs& args)
{
    if(!args.address || !args.port || !args.family) return;
    if(*args.family != transport->getLocalAddrFamily()) return;

    vector<AmStreamConnection *> new_conns;
    transport->iterateConnections(AmStreamConnection::DTLS_CONN, [&](auto conn, bool& stop) {
        CLASS_DBG("add dtls-udptl connection, state:%s, type:%s, raddr:%s, rport:%d",
                  state2str(), transport->type2str(), args.address.value().c_str(), *args.port);
        new_conns.push_back(transport->getConnFactory()->createDtlsUdptlConnection(*args.address, *args.port, conn));
    });

    transport->addConnections(new_conns);
}

const char* AmMediaSecureUdptlState::state2str()
{
    static const char *state = "DTLS-UDPTL";
    return state;
}

#include "AmMediaTransport.h"
#include "AmMediaUdptlState.h"

AmMediaUdptlState::AmMediaUdptlState(AmMediaTransport *transport)
  : AmMediaState(transport)
{
}

AmMediaState* AmMediaUdptlState::init(const AmMediaStateArgs& args)
{
    transport->setMode(AmMediaTransport::TRANSPORT_MODE_FAX);
    return AmMediaState::init(args);
}

void AmMediaUdptlState::addConnections(const AmMediaStateArgs& args)
{
    if(!args.address || !args.port) return;

    CLASS_DBG("add udptl connection, state:%s, type:%s, raddr:%s, rport:%d",
        state2str(), transport->type2str(), args.address.value().c_str(), *args.port);
    auto new_udptl_conn = transport->getConnFactory()->createUdptlConnection(*args.address, *args.port);
    transport->addConnection(new_udptl_conn, [&]() {
        transport->setCurUdptlConn(new_udptl_conn);
    });
}

const char* AmMediaUdptlState::state2str()
{
    static const char *state = "UDPTL";
    return state;
}

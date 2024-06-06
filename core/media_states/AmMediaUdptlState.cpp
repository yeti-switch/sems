#include "AmMediaUdptlState.h"

AmMediaUdptlState::AmMediaUdptlState(AmMediaTransport *transport)
  : AmMediaState(transport)
{
}

AmMediaState* AmMediaUdptlState::init(const AmArg& args)
{
    string address = args["address"].asCStr();
    int port = args["port"].asInt();
    CLASS_DBG("add udptl connection, state:%s, type:%s, raddr:%s, rport:%d",
        state2str(), transport->type2str(), address.c_str(), port);
    auto new_udptl_conn = transport->getConnFactory()->createUdptlConnection(address, port);
    transport->addConnection(new_udptl_conn, [&]() {
        transport->setCurUdptlConn(new_udptl_conn);
    });
    transport->setMode(AmMediaTransport::TRANSPORT_MODE_FAX);

    return this;
}

const char* AmMediaUdptlState::state2str()
{
    static const char *state = "UDPTL";
    return state;
}

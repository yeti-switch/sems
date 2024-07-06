#pragma once

#include "AmSdp.h"

#include <optional>
using std::optional;

class AmMediaTransport;

struct AmMediaStateArgs
{
    optional<string> address;
    optional<int> port;
    optional<bool> need_restart;
    optional<bool> dtls_srtp;
    optional<bool> sdp_offer_owner;
    optional<const vector<SdpIceCandidate>*> candidates;
    optional<int> family;
};

class AmMediaState
{
public:
    AmMediaState(AmMediaTransport *transport);
    virtual ~AmMediaState() {};
    virtual AmMediaState* init(const AmMediaStateArgs& args);
    virtual AmMediaState* update(const AmMediaStateArgs& args);
    virtual AmMediaState* allowStunConnection(const sockaddr_storage* remote_addr, uint32_t priority) { return this; };
    virtual AmMediaState* onSrtpKeysAvailable() { return this; };
    virtual void addConnections(const AmMediaStateArgs& args) {};
    virtual void updateConnections(const AmMediaStateArgs& args) {};
    virtual const char* state2str();

protected:
    AmMediaTransport* transport;
};

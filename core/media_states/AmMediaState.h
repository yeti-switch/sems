#pragma once

#include "AmMediaTransport.h"
#include "AmMediaConnectionFactory.h"

class AmMediaState
{
public:
    AmMediaState(AmMediaTransport *transport);
    virtual ~AmMediaState();

    virtual AmMediaState* init(const AmArg& args) { return this; };
    virtual AmMediaState* update(const AmArg& args) { return this; };
    virtual AmMediaState* addCandidates(const vector<SdpIceCandidate>& candidates, bool sdp_offer_owner) { return this; };
    virtual AmMediaState* allowStunConnection(sockaddr_storage* remote_addr, uint32_t priority) { return this; };
    virtual AmMediaState* onSrtpKeysAvailable() { return this; };
    virtual const char* state2str();

protected:
    AmMediaTransport* transport;
};

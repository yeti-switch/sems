#pragma once

#include "AmMediaState.h"

class AmMediaIceState
  : public virtual AmMediaState
{
public:
    AmMediaIceState(AmMediaTransport *transport);
    AmMediaState* init(const AmArg& args) override;
    AmMediaState* update(const AmArg& args) override;
    AmMediaState* addCandidates(const vector<SdpIceCandidate>& candidates, bool sdp_offer_owner) override;
    AmMediaState* allowStunConnection(sockaddr_storage* remote_addr, uint32_t priority) override;
    const char* state2str() override;

protected:
    void addStunConnections(const vector<SdpIceCandidate>& candidates, bool sdp_offer_owner);
    void removeStunConnections();
    void resetCurRtpConnection();
    AmMediaState* nextState();
    bool isSrtp();
    bool isDtls();
    bool isZrtp();
    bool isRtp();
};

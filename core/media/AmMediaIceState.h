#pragma once

#include "AmMediaState.h"

class AmMediaIceState
  : public virtual AmMediaState
{
public:
    AmMediaIceState(AmMediaTransport *transport);
    AmMediaState* init(const AmMediaStateArgs& args) override;
    AmMediaState* update(const AmMediaStateArgs& args) override;
    const char* state2str() override;

protected:
    void addStunConnections(const vector<SdpIceCandidate>* candidates, bool sdp_offer_owner);
    void removeStunConnections();
    void resetCurRtpConnection();
    AmMediaState* allowStunConnection(const sockaddr_storage* remote_addr, uint32_t priority) override;
    AmMediaState* nextState();
    bool isSrtp();
    bool isDtls();
    bool isZrtp();
    bool isRtp();
};

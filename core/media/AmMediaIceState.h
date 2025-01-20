#pragma once

#include "AmMediaState.h"

class AmStreamConnection;

class AmMediaIceState
  : public virtual AmMediaState
{
    bool is_udptl;
    void setCurrentConnection(AmStreamConnection* conn);
    bool candidate_address_is_allowed(const string& addr_str);
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
    AmMediaState* allowStunPair(const sockaddr_storage* remote_addr) override;
    AmMediaState * connectionTrafficDetected(const sockaddr_storage * remote_addr) override;
    virtual AmMediaState* nextState();
    bool isSrtp();
    bool isDtls();
    bool isZrtp();
    bool isRtp();
    bool isSecured();
};

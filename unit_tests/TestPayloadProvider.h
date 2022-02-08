#pragma once

#include "Config.h"
#include "AmPlugIn.h"

class TestPayloadProvider : public AmPayloadProvider
{
public:
    TestPayloadProvider(){}
    ~TestPayloadProvider(){}

    virtual amci_payload_t*  payload(int payload_id) const override;
    virtual int getDynPayload(const string& name, int rate, int encoding_param) const override;
    virtual void getPayloads(vector<SdpPayload>& pl_vec) const override;
};

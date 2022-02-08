#include "TestPayloadProvider.h"
#include "AmSdp.h"

amci_payload_t * TestPayloadProvider::payload(int payload_id) const
{
    return AmPlugIn::instance()->payload(payload_id);
}

int TestPayloadProvider::getDynPayload(const string& name, int rate, int encoding_param) const
{
    if(strcasecmp(test_config::instance()->stress_media_codec.c_str(), name.c_str()) != 0 &&
        name != "telephone-event") return -1;
    return AmPlugIn::instance()->getDynPayload(name, rate, encoding_param);
}

void TestPayloadProvider::getPayloads(vector<SdpPayload>& pl_vec) const
{
    vector<SdpPayload> pls;
    AmPlugIn::instance()->getPayloads(pls);
    for(auto payload : pls) {
        if(strcasecmp(payload.encoding_name.c_str(), test_config::instance()->stress_media_codec.c_str()) == 0 ||
            payload.encoding_name == "telephone-event") {
            pl_vec.push_back(payload);
        }
    }
}

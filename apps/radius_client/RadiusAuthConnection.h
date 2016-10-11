#pragma once

#include "RadiusConnection.h"

class RadiusAuthConnection: public RadiusConnection
{
    bool reject_on_error;
    AmArg raw_avps;
    avps_t avps;
  public:
    RadiusAuthConnection(
        unsigned int connection_id,
        string &name,
        string &server,
        unsigned short port,
        string &secret,
        bool reject_on_error,
        unsigned int timeout_msec,
        unsigned int attempts,
        AmArg avps);

    int init();
    void AccessRequest(const RadiusRequestEvent &req);
    void on_timeout(RadiusPacket &p);
    void on_reply(RadiusPacket &request, RadiusPacket &reply);

    void getInfo(AmArg &info);
};

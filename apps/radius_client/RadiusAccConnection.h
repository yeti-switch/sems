#pragma once

#include "RadiusConnection.h"

class RadiusAccConnection: public RadiusConnection
{
    AmArg start_avps_raw,
          interim_avps_raw,
          stop_avps_raw;

    avps_t start_avps,
           interim_avps,
           stop_avps;

    RadiusAccountingRules rules;

    void add_avps_info(const avps_t &avps, AmArg &ret);
    avps_t& get_avps(RadiusRequestEvent::RadiusAccountingType type);

  public:
    RadiusAccConnection(
        unsigned int connection_id,
        string &name,
        string &server,
        unsigned short port,
        string &secret,
        unsigned int timeout_msec,
        unsigned int attempts,
        AmArg start_avps,
        AmArg interim_avps,
        AmArg stop_avps,
        bool enable_start_accounting,
        bool enable_interim_accounting,
        bool enable_stop_accounting,
        int interim_accounting_interval);

    void get_rules(AmArg &ret) { rules.pack(ret); }

    int init();
    void AccountingRequest(const RadiusRequestEvent &req);
    void on_timeout(RadiusPacket &p);
    void on_reply(RadiusPacket &request, RadiusPacket &reply);

    void getInfo(AmArg &info);
};

#pragma once

#include <stdint.h>

#include "AmArg.h"
#include "ampi/RadiusClientAPI.h"
#include "RadiusPacket.h"

#include <string>
#include <vector>
#include <map>
#include <utility>
#include <stdint.h>
using std::string;
using std::vector;
using std::map;
using std::pair;

class RadiusConnection
{
  protected:
    unsigned int connection_id;
    string name;
    string server;
    unsigned short port;
    string secret;
    unsigned int timeout;
    unsigned int attempts;

    long long int
        requests_sent,
        replies_got,
        requests_err,
        requests_timeouts,
        replies_err,
        replies_socket_err,
        replies_match_err,
        replies_validate_err;
    double
        min_response_time,
        max_response_time;

    enum field_format {
        str,
        integer,
        octets,
        date,
        ipv4,
        ipv6
    };
    struct avp_info {
        uint8_t type;
        field_format fmt;
        string name;
        string fmt_name;
        string value;

        bool vsa;
        uint32_t vsa_vendor_id;
        uint8_t vsa_vendor_type;

        int parse(const AmArg &a);
        int add2packet(RadiusPacket *p, const map<string,string> &values_hash) const;
        void info(AmArg &info) const;
    };
    typedef vector<avp_info> avps_t;
    int parse_avps(avps_t &avps, const AmArg &raw_avps);

    uint8_t last_id;
    struct timeval timeout_tv;

    int sock;

    typedef map<uint8_t, RadiusPacket *> SentMap;
    SentMap sent_map;

  public:
    RadiusConnection(
        unsigned int connection_id,
        string &name,
        string &server,
        unsigned short port,
        string &secret,
        unsigned int timeout_msec,
        unsigned int attempts);

    virtual ~RadiusConnection();

    virtual int init();

    void process();
    void check_timeouts();

    virtual void on_timeout(RadiusPacket &p) { }
    virtual void on_reply(RadiusPacket &request, RadiusPacket &reply) = 0;

    int get_sock() const { return sock; }

    void getStat(AmArg &stat);
    virtual void getInfo(AmArg &info);
};

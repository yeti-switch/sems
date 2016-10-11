#pragma once

#include <stdint.h>
#include "AmArg.h"

#include <string>
#include <vector>
#include <map>
#include <utility>
using std::string;
using std::vector;
using std::map;
using std::pair;

#include <sys/socket.h>
#include <arpa/inet.h>

#define RAD_MAX_PACKET_SIZE 4096
#define RAD_AUTH_SIZE       16
#define RAD_STATIC_HDR_SIZE (sizeof(static_header))
#define RAD_ATTRS_SIZE      (RAD_MAX_PACKET_SIZE-RAD_STATIC_HDR_SIZE)

class RadiusPacket
{
#pragma pack(push,1)
    struct cil_header {
        uint8_t code;
        uint8_t id;
        uint16_t len;
    };
    struct static_header {
        struct cil_header cil;
        unsigned char auth[RAD_AUTH_SIZE];
    };
    struct header {
        static_header hdr;
        unsigned char attrs[RAD_ATTRS_SIZE];
    } packet;
#pragma pack(pop)

    uint8_t *attrs_tail;
    uint8_t *attrs_end;

    struct timeval expire_at;
    struct timeval netstamp;
    string request_session_id;

    unsigned int attempt;

    void init();
    void gen_auth(const string &secret);

  public:

    enum Code {
        AccessRequest = 1,
        AccessAccept = 2,
        AccessReject = 3,
        AccountingRequest = 4,
        AccountingResponse = 5
    };

    RadiusPacket();
    RadiusPacket(uint8_t code, uint8_t id);
    RadiusPacket(unsigned char *buf, unsigned int len);
    ~RadiusPacket();

    const char *buf() const { return (const char *)&packet; }
    unsigned int len() const { return ntohs(packet.hdr.cil.len); }
    const unsigned char *auth() const { return packet.hdr.auth; }
    uint8_t id() const { return packet.hdr.cil.id; }
    uint8_t code() const { return packet.hdr.cil.code; }
    const struct timeval *expire() const { return &expire_at; }
    const struct timeval *timestamp() const { return &netstamp; }
    const string &session() const { return request_session_id; }
    unsigned int get_attempt() const { return attempt; }

    void set_code(uint8_t code) { packet.hdr.cil.code = code; }
    void set_id(uint8_t id) { packet.hdr.cil.id = id; }
    void set_session_id(const string &session_id);
    void set_expire(const struct timeval &timestamp);
    void build(const string &secret);

    int add_attr(uint8_t type, const char *buf, unsigned int len);
    int add_vendor_attr(uint8_t type, uint32_t vendor_id, uint8_t vendor_type, const char *buf, unsigned int len);
    int add_attr_string(uint8_t type,const string &s);

    int add_attr_int32(uint8_t type,uint32_t i);
    int add_vendor_attr_int32(uint8_t type, uint32_t vendor_id, uint8_t vendor_type, uint32_t i);

    int send(int fd);
    int read_from_socket(int fd);

    /*! validate reply. must be called only for reply packets
      \param request appropriate request (needed to get request authenticator)
      \param secret shared secret (involved into hash computing)
      \return true for valid reply
    */
    bool validate(const RadiusPacket &request, const string &secret);
};


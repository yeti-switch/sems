#pragma once

#include "AmSessionContainer.h"
#include "BusClient.h"

#include <limits.h>
#include <string>
#include <map>
#include <queue>
#include <netinet/sctp.h>

using std::map;
using std::queue;
using std::string;

// namespace BUS {

/** "BSLG" */
#define BUS_MAGIC            0x42534C47
#define BUS_SCTP_BUFFER_SIZE (2 * 1024 * 1024)

#define PDU_TYPE_HELLO             0x0000
#define PDU_TYPE_HELLO_RESP        0x8000
#define PDU_TYPE_QUERY             0x0001
#define PDU_TYPE_QUERY_RESP        0x8001
#define PDU_TYPE_EVENT             0x0002
#define PDU_TYPE_EVENT_RESP        0x8002
#define PDU_TYPE_QUERY_PACKED      0x0003
#define PDU_TYPE_QUERY_PACKED_RESP 0x8003


#pragma pack(1)

typedef struct bus_pdu_hdr {
    uint32_t magic;
    uint16_t type; /** HELLO/RESP, QUERY/RESP, EVENT */
    uint16_t status;
    uint32_t seq;
    uint32_t length;
} bus_pdu_hdr_t;

typedef struct bus_pdu_hello {
    uint8_t  node_type;
    uint32_t node_id;
    uint32_t node_ver;
    uint64_t node_sign;
} bus_pdu_hello_t;


typedef struct bus_pdu_query {
    uint8_t src_length;
    uint8_t dst_length;
    /** addrs
        SRC[]
        DST[]
        BODY[] */
} bus_pdu_query_t;

typedef struct bus_pdu_query_packet {
    uint8_t  src_length;
    uint8_t  dst_length;
    uint32_t body_length;
    /**
        SRC[]
        DST[]
        BODY[]
        PACKET[] */
} bus_pdu_query_packet_t;

typedef struct bus_pdu_event {
    uint8_t src_length;
    uint8_t dst_length;
    /** addrs
        SRC[]
        DST[]
        BODY[] */
} bus_pdu_event_t;


typedef struct {
    bus_pdu_hdr_t hdr;

    union {
        bus_pdu_hello_t        hello;
        bus_pdu_query_t        query;
        bus_pdu_event_t        event;
        bus_pdu_query_packet_t query_packed;
    };

    struct iovec *iov;
    int           iov_len;
} bus_pdu_t;


#pragma pack()

typedef struct {
    uint8_t     addr_length;
    const void *addr;
} bsaddr_t;

class BusClient;

class BusConnection {
    typedef enum {
        BUS_PDU_HELLO = 0,
        BUS_PDU_HELLO_RESP,
        BUS_PDU_QUERY,
        BUS_PDU_QUERY_RESP,
        BUS_PDU_EVENT,
        BUS_PDU_EVENT_RESP,
        BUS_PDU_QUERY_PACKED,
        BUS_PDU_QUERY_PACKED_RESP,
        BUS_PDU_UNKNOWN
    } bus_pdu_type_t;

    typedef enum {
        BUS_PEER_TYPE_UNSPECIFIED = 0,
        BUS_PEER_TYPE_LOGIC_NODE,
        BUS_PEER_TYPE_SEMS_NODE,
        BUS_PEER_TYPE_KAMAILIO_NODE,
        BUS_PEER_TYPE_MAX
    } bus_node_type_t;


  public:
    typedef enum {
        Closed = 0,
        Connecting,
        Connected,
    } state_t;

  private:
    uint64_t node_sign;
    uint32_t node_ver;

    string payload;

    int fd, slot, node_id, reconnect_interval,
        //                            failed_count,
        so_rcvbuf, so_sndbuf;
    state_t  state;
    uint64_t last_activity;

    BusClient       *bus;
    sockaddr_storage saddr;
    static uint32_t  seq;
    uint32_t         assoc_id;

    uint32_t       e_send, e_recv, reconn, last_err;
    struct timeval connected_time;

    BusConnection() {}

    void   close();
    void   connect();
    bool   epoll_link(int op, uint32_t events);
    void   recv();
    void   handle_notification(const char *payload, int length);
    void   hello_handler(bus_pdu_t *pdu, int info_length);
    void   send_hello();
    void   pdu_handler(int status, const string &src, const string &dst, const char *body, uint32_t b_size,
                       const char *packed, uint32_t p_size);
    string inflatePacked(const char *data, uint32_t data_size);

  public:
    BusConnection(BusClient *_bus, const sockaddr_storage &_addr, int _slot, int _reconnect_interval, int node_id,
                  int _so_rcvbuf, int _so_sndbuf);
    ~BusConnection();

    void handler(uint32_t ev);
    void on_timer(uint64_t timer_val);

    bool    sendMsg(BusMsg *msg, /*out*/ uint32_t &msg_seq);
    state_t get_state() { return state; }

    void postEvent(const string &sess_id, map<string, string> &params, const AmArg &data);
    void postError(const string &sess_id, const string &err_str);

    bus_pdu_type_t get_pdu_type(uint16_t type)
    {
        switch (type) {
        case PDU_TYPE_HELLO:             return BUS_PDU_HELLO;
        case PDU_TYPE_HELLO_RESP:        return BUS_PDU_HELLO_RESP;
        case PDU_TYPE_QUERY:             return BUS_PDU_QUERY;
        case PDU_TYPE_QUERY_RESP:        return BUS_PDU_QUERY_RESP;
        case PDU_TYPE_QUERY_PACKED:      return BUS_PDU_QUERY_PACKED;
        case PDU_TYPE_QUERY_PACKED_RESP: return BUS_PDU_QUERY_PACKED_RESP;
        case PDU_TYPE_EVENT:             return BUS_PDU_EVENT;
        case PDU_TYPE_EVENT_RESP:        return BUS_PDU_EVENT_RESP;
        default:                         return BUS_PDU_UNKNOWN;
        }
    }

    static const char *state_to_str(state_t type)
    {
        static const char *st2s[] = { "Closed", "Connecting", "Connected" };
        return st2s[type];
    }

    void getInfo(AmArg &ret);

    const char *pdu_type_to_str(bus_pdu_type_t type)
    {
        static const char *t2s[] = { "BUS_PDU_HELLO",        "BUS_PDU_HELLO_RESP",
                                     "BUS_PDU_QUERY",        "BUS_PDU_QUERY_RESP",
                                     "BUS_PDU_EVENT",        "BUS_PDU_EVENT_RESP",
                                     "BUS_PDU_QUERY_PACKED", "BUS_PDU_QUERY_PACKED_RESP",
                                     "BUS_PDU_UNKNOWN" };
        return t2s[type];
    }
};

#pragma once

#include "ampi/SctpBusAPI.h"

#include <stdint.h>
#include <sys/socket.h>
#include <limits.h>

#include <unordered_map>

#define sctp_sys_err(fmt, args...) \
do { \
    ERROR(fmt ": %m",##args); \
    return -1; \
} while(0)\

#define DEFAULT_REPLY_TIMEOUT_SECONDS 60

class SctpConnection {
  protected:
    int fd;
    int epoll_fd;
    int _id;
    sockaddr_storage addr;
    char payload[USHRT_MAX];

    typedef enum {
        Closed = 0,
        Connecting,
        Connected,
    } state_t;
    state_t state;

    struct sent_info {
        time_t expire_time;
        SctpBusRawRequest req;
        sent_info(const SctpBusRawRequest &req)
          : req(req)
        {
            if(req.reply_timeout) {
                expire_time = time(nullptr) + req.reply_timeout;
            } else {
                expire_time = DEFAULT_REPLY_TIMEOUT_SECONDS;
            }
        }
    };
    uint64_t last_cseq;
    std::unordered_map<uint64_t, sent_info> sent_requests;

    string event_sink;

  public:
    SctpConnection();
    virtual ~SctpConnection();

    int sctp_recvmsg(int s, void *msg, size_t len, struct sockaddr *from,
             socklen_t *fromlen, struct sctp_sndrcvinfo *sinfo,
             int *msg_flags);

    operator int() { return -fd; }
    int get_sock() { return fd; }
    void set_epoll_fd(int efd) { epoll_fd = efd; }
    void set_addr(const sockaddr_storage &a) { addr = a; }
    void set_id(int id) { _id = id; }
    int close();

    void set_event_sink(const string &sink) { event_sink = sink; }
    const string & get_event_sink() { return event_sink; }

    virtual int process(uint32_t events) = 0;
    virtual void handle_notification(const sockaddr_storage &from) = 0;

    virtual int on_timer(time_t now) = 0;
    virtual void send(const SctpBusSendEvent &e) {}
    virtual void send(const SctpBusRawRequest &e) { }
    virtual void send(const SctpBusRawReply &e) { }

    virtual void getInfo(AmArg &info) = 0;
};


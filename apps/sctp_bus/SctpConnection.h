#pragma once

#include <stdint.h>
#include <sys/socket.h>

#include "ampi/SctpBusAPI.h"

#include <limits.h>

#define sctp_sys_err(fmt, args...) \
do { \
    ERROR(fmt ": %m",##args); \
    return -1; \
} while(0)\

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
  public:
    SctpConnection();
    virtual ~SctpConnection();

    int sctp_recvmsg(int s, void *msg, size_t len, struct sockaddr *from,
             socklen_t *fromlen, struct sctp_sndrcvinfo *sinfo,
             int *msg_flags);

    operator int() { return fd; }
    int get_sock() { return fd; }
    void set_epoll_fd(int efd) { epoll_fd = efd; }
    void set_addr(const sockaddr_storage &a) { addr = a; }
    void set_id(int id) { _id = id; }
    void close();

    virtual void process(uint32_t events) = 0;
    virtual void handle_notification(const sockaddr_storage &from) = 0;

    virtual void on_timer() {}
    virtual void send(const SctpBusSendEvent &e) {}

    virtual void getInfo(AmArg &info) = 0;
};


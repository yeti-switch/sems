#pragma once

#include "SctpConnection.h"

class SctpClientConnection
  : public SctpConnection
{
    uint32_t assoc_id;
    struct timeval last_connect_attempt;
    int reconnect_interval;
    unsigned long events_sent;
  public:
    int init(int efd, const sockaddr_storage &a, int reconnect_seconds);
    int connect();

    void process(uint32_t events);
    void handle_notification(const sockaddr_storage &from);
    void recv();
    void on_timer();

    virtual void send(const SctpBusSendEvent &e);

    void getInfo(AmArg &info);
};


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

    int process(uint32_t events) override;
    void handle_notification(const sockaddr_storage &from);
    int recv();
    int on_timer() override;

    virtual void send(const SctpBusSendEvent &e);

    void getInfo(AmArg &info);
};


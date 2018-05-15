#pragma once

#include "SctpConnection.h"
#include "SctpBusPDU.pb.h"

class SctpClientConnection
  : public SctpConnection
{
    uint32_t assoc_id;

    struct timeval last_connect_attempt;
    int reconnect_interval;
    unsigned long events_sent;
    AmDynInvoke *json_rpc;

  public:

    SctpClientConnection()
      : events_sent(0),
        json_rpc(nullptr)
    {}

    int init(int efd, const sockaddr_storage &a, int reconnect_seconds,
             const string &sink = string());
    int connect();

    int process(uint32_t events) override;
    void handle_notification(const sockaddr_storage &from);
    int recv();
    int on_timer(time_t now) override;

    virtual void send(const SctpBusSendEvent &e);
    void send(const SctpBusRawRequest &e) override;
    void send(const SctpBusRawReply &e) override;

    void onIncomingPDU(const SctpBusPDU &e);

    void getInfo(AmArg &info);
};


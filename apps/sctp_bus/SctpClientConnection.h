#pragma once

#include "SctpConnection.h"
#include "SctpBusPDU.pb.h"

class SctpClientConnection : public SctpConnection {
    uint32_t assoc_id;

    struct timeval last_connect_attempt;
    int            reconnect_interval;
    unsigned long  events_sent;
    AmDynInvoke   *json_rpc;
    AtomicCounter &connection_status;
    AtomicCounter &connection_send_failed;

    void setState(state_t st) override;

  public:
    SctpClientConnection()
        : assoc_id(-1)
        , events_sent(0)
        , json_rpc(nullptr)
        , connection_status(stat_group(Gauge, MOD_NAME, "connection_status")
                                .setHelp("sctp client connection status")
                                .addAtomicCounter())
        , connection_send_failed(stat_group(Counter, MOD_NAME, "connection_send_failed")
                                     .setHelp("count failed events send of sctp client connection")
                                     .addAtomicCounter())
    {
    }

    int init(int efd, const sockaddr_storage &a, int reconnect_seconds, const string &sink = string());
    int connect();

    int  process(uint32_t events) override;
    void handle_notification(const sockaddr_storage &from) override;
    int  recv();
    int  on_timer(time_t now) override;

    virtual void send(const SctpBusSendEvent &e) override;
    void         send(const SctpBusRawRequest &e) override;
    void         send(const SctpBusRawReply &e) override;

    void onIncomingPDU(const SctpBusPDU &e);

    void getInfo(AmArg &info) override;
};

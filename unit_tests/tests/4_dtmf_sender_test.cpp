#include <gtest/gtest.h>

#include "AmRtpStream.h"
#include "AmDtmfSender.h"

class AmStreamConnectionMock : public AmStreamConnection {
    std::function<void(AmRtpPacket *)> send_callback;

  public:
    AmStreamConnectionMock(AmMediaTransport *_transport, std::function<void(AmRtpPacket *)> send_callback)
        : AmStreamConnection(_transport, "127.0.0.1", 0, ConnectionType::RTP_CONN)
        , send_callback(send_callback)
    {
    }
    virtual void handleConnection(uint8_t *, unsigned int, struct sockaddr_storage *, struct timeval) override {}
    ssize_t      send(AmRtpPacket *packet) override
    {
        send_callback(packet);
        return 0;
    }
};

class AmMediaTransportMock : public AmMediaTransport {
  public:
    explicit AmMediaTransportMock(AmRtpStream *stream, std::function<void(AmRtpPacket *)> send_callback)
        : AmMediaTransport(stream, 0, 0, 0)
    {
        setCurRtpConn(new AmStreamConnectionMock(this, send_callback));
    }
};

class AmRtpStreamMock : public AmRtpStream {
    std::unique_ptr<AmMediaTransportMock> _transport;

  public:
    explicit AmRtpStreamMock(std::function<void(AmRtpPacket *)> send_callback)
        : AmRtpStream(nullptr, 0)
    {
        _transport.reset(new AmMediaTransportMock(this, send_callback));
        cur_rtp_trans = _transport.get();
    }
};

TEST(DtmfSenderTest, EndEventBackwardDuration)
{
    AmDtmfSender                                      sender;
    std::optional<decltype(dtmf_payload_t::duration)> last_duration = 0;

    AmRtpStreamMock stream([&](AmRtpPacket *p) {
        auto dtmf     = reinterpret_cast<const dtmf_payload_t &>(*p->getData());
        auto duration = ntohs(dtmf.duration);
        if (last_duration) {
            GTEST_ASSERT_GE(duration, last_duration.value());
        }
        last_duration = duration;
    });

    sender.queueEvent(9 /* key */, 298 /* duration */, 20 /* volume */, 8000 /* rate */, 20 /* frame_size */);
    for (auto ts = 849056240u; ts < 849056240u + 160 * 30; ts += 160) {
        sender.sendPacket(ts, 0, &stream);
    }
}

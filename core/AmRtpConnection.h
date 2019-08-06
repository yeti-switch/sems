#ifndef AM_RTP_CONNECTION_H
#define AM_RTP_CONNECTION_H

#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#include <string>
using std::string;

class AmRtpTransport;
class AmRtpPacket;

class AmStreamConnection
{
public:
    enum ConnectionType
    {
        RTP_CONN,
        RTCP_CONN,
        STUN_CONN,
        DTLS_CONN,
        RAW_CONN,

        UNKNOWN_CONN
    };
    AmStreamConnection(AmRtpTransport* _transport, const string& remote_addr, int remote_port, ConnectionType type);
    virtual ~AmStreamConnection();

    bool isUseConnection(ConnectionType type);
    bool isAddrConnection(struct sockaddr_storage* recv_addr);
    ConnectionType getConnType();
    virtual int send(AmRtpPacket* packet);
    virtual void handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time) = 0;
    virtual void setRAddr(const string& addr, unsigned short port) { resolveRemoteAddress(addr, port); }
    virtual bool getPassiveMode() { return false; }
    virtual void setPassiveMode(bool p) {}
    string getRHost() { return r_host; }
    int getRPort() { return r_port; }
    void getRAddr(sockaddr_storage* addr) { memcpy(addr, &r_addr, sizeof(sockaddr_storage)); }
    bool isMute() { return mute; }
    AmRtpTransport* getTransport() { return transport; }
protected:
    void resolveRemoteAddress(const string& remote_addr, int remote_port);
protected:
    AmRtpTransport* transport;
    string r_host;
    int r_port;
    struct sockaddr_storage r_addr;
    ConnectionType conn_type;
    bool mute;
};

class AmRawConnection : public AmStreamConnection
{
public:
    AmRawConnection(AmRtpTransport* _transport, const string& remote_addr, int remote_port)
    : AmStreamConnection(_transport, remote_addr, remote_port, AmStreamConnection::RAW_CONN) {}
    virtual void handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time) override {}
};

class AmRtpConnection : public AmStreamConnection
{
public:
    AmRtpConnection(AmRtpTransport* _transport, const string& remote_addr, int remote_port);
    AmRtpConnection(AmStreamConnection* parent, AmRtpTransport* _transport, const string& remote_addr, int remote_port);
    virtual ~AmRtpConnection();

    void setSymmetricRtpEndless(bool endless);
    void handleSymmetricRtp(struct sockaddr_storage* recv_addr);

    void setPassiveMode(bool p) override;
    virtual bool getPassiveMode() override { return passive; }

    virtual void handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time) override;
protected:
    AmStreamConnection* parent;
    /** symmetric RTP | RTCP */
    bool passive;
    struct timeval passive_set_time;
    unsigned int   passive_packets;

    /** endless symmetric rtp switching */
    bool            symmetric_rtp_endless;

    /** Timestamp of the last received RTP packet */
    struct timeval last_recv_time;
};

class AmRtcpConnection : public AmStreamConnection
{
public:
    AmRtcpConnection(AmRtpTransport* _transport, const string& remote_addr, int remote_port);
    AmRtcpConnection(AmStreamConnection* parent, AmRtpTransport* _transport, const string& remote_addr, int remote_port);
    virtual ~AmRtcpConnection();

    virtual void handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time) override;
private:
    AmStreamConnection* parent;
};

#endif/*AM_STREAM_CONNECTION_H*/

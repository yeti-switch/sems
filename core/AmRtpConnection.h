#ifndef AM_RTP_CONNECTION_H
#define AM_RTP_CONNECTION_H

#include <stdint.h>
#include <sys/socket.h>

#include <string>
using std::string;

class AmRtpTransport;

class AmStreamConnection
{
public:
    enum ConnectionType
    {
        RTP_CONN,
        RTCP_CONN,
        STUN_CONN,
        DTLS_CONN,

        UNKNOWN_CONN
    };
    AmStreamConnection(AmRtpTransport* _transport, const string& remote_addr, int remote_port, ConnectionType type);
    virtual ~AmStreamConnection();

    bool isUseConnection(ConnectionType type);
    bool isAddrConnection(struct sockaddr_storage* recv_addr);
    virtual void handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time) = 0;
protected:
    AmRtpTransport* transport;
    string r_host;
    int r_port;
    struct sockaddr_storage r_addr;
    ConnectionType conn_type;
};

class AmRtpConnection : public AmStreamConnection
{
public:
    AmRtpConnection(AmRtpTransport* _transport, const string& remote_addr, int remote_port);
    virtual ~AmRtpConnection();

    void setSymmetricRtpEndless(bool endless);
    void handleSymmetricRtp(struct sockaddr_storage* recv_addr);

    virtual void handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time);
protected:
    /** symmetric RTP | RTCP */
    bool passive;
    struct timeval passive_set_time;
    unsigned int   passive_packets;
    /** endless symmetric rtp switching */
    bool            symmetric_rtp_endless;

    /** Timestamp of the last received RTP packet */
    struct timeval last_recv_time;
};

#endif/*AM_STREAM_CONNECTION_H*/

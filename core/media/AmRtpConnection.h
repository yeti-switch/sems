#ifndef AM_RTP_CONNECTION_H
#define AM_RTP_CONNECTION_H

#include <string.h>
#include <sys/socket.h>
#include "AmArg.h"
#include "ObjectsCounter.h"

#include <cstdint>
#include <string>
using std::string;

class AmMediaTransport;
class AmRtpPacket;

class AmStreamConnection
  : public atomic_ref_cnt
#ifdef OBJECTS_COUNTER
  , ObjCounter(AmStreamConnection)
#endif
{
public:
    enum ConnectionError {
        RTP_BUFFER_SIZE_ERROR = 0,
        RTP_PARSER_ERROR = 0,

        DTLS_ERROR,

        SRTP_KEY_ERROR,
        SRTP_INIT_ERROR,
        SRTP_CREATION_ERROR,
        SRTP_ADD_STREAM_ERROR,
        SRTP_UNPROTECT_ERROR,
        SRTP_PROTECT_ERROR,

        STUN_DROPPED_ERROR,
        STUN_VALID_ERROR,

        UNKNOWN_ERR
    };

    enum ConnectionType
    {
        RTP_CONN = 0,
        RTCP_CONN,
        STUN_CONN,
        DTLS_CONN,
        UDPTL_CONN,
        ZRTP_CONN,
        RAW_CONN,

        UNKNOWN_CONN
    };

    static string connType2Str(ConnectionType type);

    AmStreamConnection(AmMediaTransport* _transport, const string& remote_addr, int remote_port, ConnectionType type);
    AmStreamConnection(AmStreamConnection* _parent, const string& remote_addr, int remote_port, ConnectionType type);
    virtual ~AmStreamConnection();

    virtual bool isUseConnection(ConnectionType type);
    bool isAddrConnection(struct sockaddr_storage* recv_addr);
    ConnectionType getConnType();
    virtual ssize_t send(AmRtpPacket* packet);
    virtual void process_packet(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time);
    virtual void handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time) = 0;
    virtual void setRAddr(const string& addr, unsigned short port);
    virtual bool getPassiveMode() { return passive; }
    virtual void setPassiveMode(bool p);
    virtual void handleSymmetricRtp(struct sockaddr_storage* recv_addr, struct timeval* recv_time);
    string getRHost() { return r_host; }
    int getRPort() { return r_port; }
    void getRAddr(sockaddr_storage* addr) { memcpy(addr, &r_addr, sizeof(sockaddr_storage)); }
    bool isMute() { return mute; }
    AmMediaTransport* getTransport() { return transport; }
    void getInfo(AmArg& ret);
protected:
    void resolveRemoteAddress(const string& remote_addr, int remote_port);
protected:
    AmMediaTransport* transport;
    AmStreamConnection* parent;
    string r_host;
    int r_port;
    struct sockaddr_storage r_addr;
    ConnectionType conn_type;
    bool mute;

    /** symmetric RTP | RTCP */
    bool passive;
    /** Timestamp of the last received RTP packet */
    struct timeval last_recv_time;
    struct timeval passive_set_time;
    unsigned int   passive_packets;
    unsigned int   dropped_by_raddr_packets;
};

class AmRawConnection : public AmStreamConnection
{
public:
    AmRawConnection(AmMediaTransport* _transport, const string& remote_addr, int remote_port);
    virtual void handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time) override;
};

class AmRtpConnection : public AmStreamConnection
{
public:
    AmRtpConnection(AmMediaTransport* _transport, const string& remote_addr, int remote_port);
    AmRtpConnection(AmStreamConnection* _parent, const string& remote_addr, int remote_port);
    virtual ~AmRtpConnection();

    virtual void handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time) override;
};

class AmRtcpConnection : public AmStreamConnection
{
public:
    AmRtcpConnection(AmMediaTransport* _transport, const string& remote_addr, int remote_port);
    AmRtcpConnection(AmStreamConnection* _parent, const string& remote_addr, int remote_port);
    virtual ~AmRtcpConnection();

    virtual void handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time) override;
};

#endif/*AM_STREAM_CONNECTION_H*/

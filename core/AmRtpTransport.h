#ifndef AM_RTP_TRANSPORT_H
#define AM_RTP_TRANSPORT_H

#include "AmRtpSession.h"
#include "AmRtpConnection.h"
#include "AmArg.h"
#include "AmSdp.h"

#include "sip/ip_util.h"
#include "sip/types.h"
#include "sip/msg_logger.h"
#include "sip/msg_sensor.h"

class AmRtpStream;
class AmRtpPacket;

#define RTP_PACKET_BUF_SIZE 4096
#define RTP_PACKET_TIMESTAMP_DATASIZE (CMSG_SPACE(sizeof(struct timeval)))

#define RTP_TRANSPORT   1
#define RTCP_TRANSPORT  2

class AmRtpTransport : public AmObject,
                       public AmRtpSession
{
public:
    AmRtpTransport(AmRtpStream* _stream, int _if, int _proto_id, int tr_type);
    ~AmRtpTransport();

    int getTransportType() { return type; }

    int getLocalIf() { return l_if; }
    int getLocalProtoId() { return lproto_id; }

    /** set destination for logging all received/sent packets */
    void setLogger(msg_logger *_logger);
    void setSensor(msg_sensor *_sensor);

    /**
    * Gets RTP local address. If no RTP address in assigned, assigns a new one.
    * @param out local RTP addess.
    */
    string getLocalIP();

    /**
    * Gets RTP local address. If no RTP address in assigned, assigns a new one.
    * @param out local RTP addess.
    */
    void getLocalAddr(struct sockaddr_storage* addr);

    /**
    * Gets RTP port number. If no RTP port in assigned, assigns a new one.
    * @return local RTP port.
    */
    int getLocalPort();

    /**
    * Gets remote host IP.
    * @return remote host IP.
    */
    string getRHost(bool rtcp);

    /**
    * Gets remote RTP port.
    * @return remote RTP port.
    */
    int getRPort(bool rtcp);

    /**
    * Initializes with a new random local port if 'p' is 0,
    * else binds the given port, and sets own attributes properly.
    */
    void setLocalPort(unsigned short p = 0);

    /**
    * Set remote IP & port.
    */
    void setRAddr(const string& addr, unsigned short port);

    void addConnection(AmStreamConnection* conn);
    void removeConnection(AmStreamConnection* conn);

    int send(AmRtpPacket* packet, AmStreamConnection::ConnectionType type);
    int send(sockaddr_storage* raddr, unsigned char* buf, int size, AmStreamConnection::ConnectionType type);
    int sendmsg(unsigned char* buf, int size);

    void allowStunConnection(sockaddr_storage* remote_addr);
    void dtlsSessionActivated(uint16_t srtp_profile, const vector<uint8_t>& local_key, const vector<uint8_t>& remote_key);

    void stopReceiving();
    void resumeReceiving();

    void setPassiveMode(bool p);
    bool getPassiveMode();

    /** returns the socket descriptor for local socket (initialized or not) */
    int hasLocalSocket();
    /** initializes and gets the socket descriptor for local socket */
    int getLocalSocket(bool reinit = false);
    /** set options to the socket descriptor for local socket */
    void setSocketOption();
    void addToReceiver();

    void initIceConnection(const SdpMedia& local_media, const SdpMedia& remote_media);
    void initRtpConnection(const string& remote_address, int remote_port);
    void initRtcpConnection(const string& remote_address, int remote_port);
    void initSrtpConnection(const string& remote_address, int remote_port, const SdpMedia& local_media, const SdpMedia& remote_media);
    void initDtlsConnection(const string& remote_address, int remote_port, const SdpMedia& local_media, const SdpMedia& remote_media);

    AmRtpStream* getRtpStream() { return stream; }
protected:
    int recv(int sd);

    void recvPacket(int fd) override;


    void log_rcvd_packet(const char *buffer, int len, struct sockaddr_storage &recv_addr, AmStreamConnection::ConnectionType type);
    void log_sent_packet(const char *buffer, int len, struct sockaddr_storage &send_addr, AmStreamConnection::ConnectionType type);

    AmStreamConnection::ConnectionType GetConnectionType(unsigned char* buf, int size);
    bool isStunMessage(unsigned char* buf, unsigned int size);
    bool isRTPMessage(unsigned char* buf, unsigned int size);
    bool isDTLSMessage(unsigned char* buf, unsigned int size);
    bool isRTCPMessage(unsigned char* buf, unsigned int size);

    msg_sensor::packet_type_t streamConnType2sensorPackType(AmStreamConnection::ConnectionType type);
private:
    enum {
        NONE,
        ICE,
        DTLS,
        SRTP,
        RTP
    } seq;
    msg_logger *logger;
    msg_sensor *sensor;

    /** Stream owning this transport */
    AmRtpStream* stream;
    AmStreamConnection* cur_rtp_stream;
    AmStreamConnection* cur_rtcp_stream;

    /** transport type */
    int type;

    /** Local socket */
    int                l_sd;

    /** Context index in receiver for local socket */
    int                l_sd_ctx;

    /** Local port */
    unsigned short     l_port;

    /**
    * Local interface used for this stream
    * (index into @AmLcConfig::Ifs)
    */
    int l_if;

    /**
    * Local addr index from local interface
    * (index into @AmLcConfig::Ifs.proto_info)
    */
    int lproto_id;

    struct sockaddr_storage l_saddr;

    msghdr recv_msg;
    iovec recv_iov[1];
    unsigned int   b_size;
    unsigned char  buffer[RTP_PACKET_BUF_SIZE];
    unsigned char recv_ctl_buf[RTP_PACKET_TIMESTAMP_DATASIZE];
    struct timeval recv_time;
    struct sockaddr_storage saddr;

    vector<AmStreamConnection*> connections;
};

#endif/*AM_RTP_TRANSPORT_H*/

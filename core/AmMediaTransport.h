#ifndef AM_RTP_TRANSPORT_H
#define AM_RTP_TRANSPORT_H

#include "AmRtpSession.h"
#include "AmRtpConnection.h"
#include "AmDtlsConnection.h"
#include "AmArg.h"
#include "AmSdp.h"

#include "sip/ip_util.h"
#include "sip/types.h"
#include "sip/msg_logger.h"
#include "sip/msg_sensor.h"
#include "sip/ssl_settings.h"

class AmRtpStream;
class AmRtpPacket;

#define RTP_PACKET_BUF_SIZE 4096
#define RTP_PACKET_TIMESTAMP_DATASIZE (CMSG_SPACE(sizeof(struct timeval)))

#define RAW_TRANSPORT       0
#define RTP_TRANSPORT       1
#define RTCP_TRANSPORT      2
#define FAX_TRANSPORT       3

class AmMediaTransport : public AmObject,
                       public AmRtpSession
{
public:
    enum Mode {
        TRANSPORT_MODE_DEFAULT,
        TRANSPORT_MODE_FAX,
        TRANSPORT_MODE_DTLS_FAX,
        TRANSPORT_MODE_RAW
    };

    AmMediaTransport(AmRtpStream* _stream, int _if, int _proto_id, int type);
    virtual ~AmMediaTransport();

    int getTransportType() { return type; }
    void setTransportType(int _type) { type = _type; }

    int getLocalIf() { return l_if; }
    int getLocalProtoId() { return lproto_id; }

    bool isSrtpEnable() { return srtp_enable; }
    bool isDtlsEnable() { return dtls_enable; }

    /** set destination for logging all received/sent packets */
    void setLogger(msg_logger *_logger);
    void setSensor(msg_sensor *_sensor);

    bool isMute();

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
    * Initializes with a new random local port if 'p' is 0,
    * else binds the given port, and sets own attributes properly.
    */
    void setLocalPort(unsigned short p = 0);

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
    * Gets remote addr.
    */
    void getRAddr(bool rtcp, sockaddr_storage* addr);
    void getRAddr(sockaddr_storage* addr);

    /**
    * Set remote IP & port.
    */
    void setRAddr(const string& addr, unsigned short port);

    /**
    * Set transport mode.
    */
    void setMode(Mode mode);

    void addConnection(AmStreamConnection* conn);
    void removeConnection(AmStreamConnection* conn);

    ssize_t send(AmRtpPacket* packet, AmStreamConnection::ConnectionType type);
    ssize_t send(sockaddr_storage* raddr, unsigned char* buf, int size, AmStreamConnection::ConnectionType type);
    int sendmsg(unsigned char* buf, int size);

    void allowStunConnection(sockaddr_storage* remote_addr, int priority);
    void dtlsSessionActivated(uint16_t srtp_profile, const vector<uint8_t>& local_key, const vector<uint8_t>& remote_key);
    void onRtpPacket(AmRtpPacket* packet, AmStreamConnection* conn);
    void onRtcpPacket(AmRtpPacket* packet, AmStreamConnection* conn);
    void onRawPacket(AmRtpPacket* packet, AmStreamConnection* conn);

    void updateStunTimers();

    void stopReceiving();
    void resumeReceiving();

    void setPassiveMode(bool p);
    bool getPassiveMode() { return cur_rtp_conn ? cur_rtp_conn->getPassiveMode() : false;}

    /** returns the socket descriptor for local socket (initialized or not) */
    int hasLocalSocket();
    /** initializes and gets the socket descriptor for local socket */
    int getLocalSocket(bool reinit = false);

    /**
    * Generate an SDP offer based on the stream capabilities.
    * @param index index of the SDP media within the SDP.
    * @param offer the local offer to be filled/completed.
    */
    void getSdpOffer(SdpMedia& offer);
    /**
    * Generate an answer for the given SDP media based on the stream capabilities.
    * @param index index of the SDP media within the SDP.
    * @param offer the remote offer.
    * @param answer the local answer to be filled/completed.
    */
    void getSdpAnswer(const SdpMedia& offer, SdpMedia& answer);
    void getIceCandidate(SdpMedia& media);
    
    void initIceConnection(const SdpMedia& local_media, const SdpMedia& remote_media);
    void initRtpConnection(const string& remote_address, int remote_port);
    void initSrtpConnection(const string& remote_address, int remote_port, const SdpMedia& local_media, const SdpMedia& remote_media);
    void initSrtpConnection(uint16_t srtp_profile, const string& local_key, const string& remote_key);
    void initDtlsConnection(const string& remote_address, int remote_port, const SdpMedia& local_media, const SdpMedia& remote_media);
    void initUdptlConnection(const string& remote_address, int remote_port);
#ifdef WITH_ZRTP
    void initZrtpConnection(const string& remote_address, int remote_port);
#endif/*WITH_ZRTP*/
    void initRawConnection();

    AmRtpStream* getRtpStream() { return stream; }
protected:
    void addSrtpConnection(const string& remote_address, int remote_port, int srtp_ptrofile, const string& local_key, const string& remote_key);
    void addRtpConnection(const string& remote_address, int remote_port);

    ssize_t recv(int sd);
    void recvPacket(int fd) override;

    virtual void onPacket(unsigned char* buf, unsigned int size, sockaddr_storage& addr, struct timeval recvtime);

    void log_rcvd_packet(const char *buffer, int len, struct sockaddr_storage &recv_addr, AmStreamConnection::ConnectionType type);
    void log_sent_packet(const char *buffer, int len, struct sockaddr_storage &send_addr, AmStreamConnection::ConnectionType type);

    int getSrtpCredentialsBySdp(const SdpMedia& local_media, const SdpMedia& remote_media, string& local_key, string& remote_key);
public:
    AmStreamConnection::ConnectionType GetConnectionType(unsigned char* buf, unsigned int size);
    bool isStunMessage(unsigned char* buf, unsigned int size);
    bool isRTPMessage(unsigned char* buf, unsigned int size);
    bool isDTLSMessage(unsigned char* buf, unsigned int size);
    bool isRTCPMessage(unsigned char* buf, unsigned int size);
    bool isZRTPMessage(unsigned char* buf, unsigned int size);

    msg_sensor::packet_type_t streamConnType2sensorPackType(AmStreamConnection::ConnectionType type);
protected:
    enum {
        TRANSPORT_SEQ_NONE,
        TRANSPORT_SEQ_ICE,
        TRANSPORT_SEQ_DTLS,
        TRANSPORT_SEQ_SRTP,
        TRANSPORT_SEQ_RTP,
        TRANSPORT_SEQ_UDPTL,
        TRANSPORT_SEQ_RAW,
        TRANSPORT_SEQ_ZRTP
    } seq;

    Mode mode;

    /** Stream owning this transport */
    AmRtpStream* stream;
    AmStreamConnection* cur_rtp_conn;
    AmStreamConnection* cur_rtcp_conn;
    AmStreamConnection* cur_raw_conn;

    AmStreamConnection* getSuitableConnection(bool rtcp);
private:
    msg_logger *logger;
    msg_sensor *sensor;

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
    
    dtls_client_settings client_settings;
    dtls_server_settings server_settings;
    vector<CryptoProfile> srtp_profiles;
    bool srtp_enable;
    bool dtls_enable;
    bool zrtp_enable;

    vector<AmStreamConnection*> connections;
    AmMutex                     connections_mut;
    AmMutex                     stream_mut;
};

#endif/*AM_RTP_TRANSPORT_H*/

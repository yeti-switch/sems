#ifndef AM_RTP_TRANSPORT_H
#define AM_RTP_TRANSPORT_H

#include "AmRtpSession.h"
#include "AmStunConnection.h"
#include "AmSrtpConnection.h"

#include "AmArg.h"
#include "AmSdp.h"
#include "AmMediaConnectionFactory.h"
#include "AmMediaConnectionsHolder.h"

#include "AmMediaState.h"
#include "AmMediaRtpState.h"
#include "AmMediaSrtpState.h"
#include "AmMediaZrtpState.h"
#include "AmMediaDtlsState.h"
#include "AmMediaIceState.h"
#include "AmMediaUdptlState.h"

#include "sip/ip_util.h"
#include "sip/types.h"
#include "sip/msg_logger.h"
#include "sip/msg_sensor.h"
#include "sip/ssl_settings.h"

class AmRtpStream;
class AmRtpPacket;
class AmMediaState;

#define RTP_PACKET_BUF_SIZE 4096
#define RTP_PACKET_TIMESTAMP_DATASIZE (CMSG_SPACE(sizeof(struct timeval)))

#define RAW_TRANSPORT       0
#define RTP_TRANSPORT       1
#define RTCP_TRANSPORT      2
#define FAX_TRANSPORT       3

#define MAX_TRANSPORT_TYPE  4

class AmMediaTransport
  : public AmMediaConnectionsHolder,
    public AmRtpSession
#ifdef OBJECTS_COUNTER
    , ObjCounter(AmMediaTransport)
#endif
{
    AmMutex state_mutex;
    unique_ptr<AmMediaState> state;
    AmMediaConnectionFactory conn_factory;

public:
    enum Mode {
        TRANSPORT_MODE_DEFAULT,
        TRANSPORT_MODE_FAX,
        TRANSPORT_MODE_DTLS_FAX,
        TRANSPORT_MODE_RAW
    };

    AmMediaTransport(AmRtpStream* _stream, int _if, int _proto_id, int type);
    virtual ~AmMediaTransport();

    template<class T> void updateState(AmMediaStateArgs& args) {
        AmLock l(state_mutex);
        args.family = getLocalAddrFamily();
        AmMediaState* next_state = nullptr;
        if(!state) {
            next_state = new T(this);
            next_state = next_state->init(args);
        } else {
            next_state = state->update(args);
        }

        if(state.get() != next_state)
            state.reset(next_state);
    }
    void allowStunConnection(const sockaddr_storage* remote_addr, uint32_t priority);
    void onSrtpKeysAvailable();
    const char* state2str();
    const char* state2strUnsafe();

    int getTransportType() { return type; }
    void setTransportType(int _type) { type = _type; }

    int getLocalIf() { return l_if; }
    int getLocalProtoId() { return lproto_id; }
    AddressType getLocalAddrType() { return getLocalAddrFamily() == AF_INET ? AT_V4 : AT_V6; }
    int getLocalAddrFamily() { return l_saddr.ss_family; }

    bool isSrtpEnable() { return srtp_enable; }
    bool isDtlsEnable() { return dtls_enable; }
    bool isZrtpEnable() { return zrtp_enable; }

    /** set destination for logging all received/sent packets */
    void setLogger(msg_logger *_logger);
    void setSensor(msg_sensor *_sensor);

    bool isMute(AmStreamConnection::ConnectionType type);

    /**
    * Gets RTP local ip.
    * @param out local RTP ip.
    */
    string getLocalIP();

    /**
    * Gets RTP local port.
    * @param out local RTP port.
    */    
    unsigned short getLocalPort();

    /**
    * Gets RTP local address.
    * @param out local RTP addess.
    */
    void getLocalAddr(struct sockaddr_storage* addr);

    /**
    * Sets RTP local address.
    * @param in local RTP addess.
    */
    void setLocalAddr(struct sockaddr_storage* addr);

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

    ssize_t send(AmRtpPacket* packet, AmStreamConnection::ConnectionType type);
    virtual ssize_t send(sockaddr_storage* raddr, unsigned char* buf, int size, AmStreamConnection::ConnectionType type);
    int sendmsg(unsigned char* buf, int size);

    void dtls_alert(string alert);
    void onRtpPacket(AmRtpPacket* packet, AmStreamConnection* conn);
    void onRtcpPacket(AmRtpPacket* packet, AmStreamConnection* conn);
    void onRawPacket(AmRtpPacket* packet, AmStreamConnection* conn);

    void updateStunTimers();

    void stopReceiving();
    void resumeReceiving();

    void setPassiveMode(bool p);
    bool getPassiveMode() { return getCurRtpConn() ? getCurRtpConn()->getPassiveMode() : false;}

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
    void prepareIceCandidate(SdpIceCandidate& candidate);
    uint32_t getCurrentConnectionPriority();
    void storeAllowedIceAddr(const sockaddr_storage* remote_addr, uint32_t priority);
    sockaddr_storage* getAllowedIceAddr();
    void removeAllowedIceAddrs();
    void setIcePriority(unsigned int priority);
    void getInfo(AmArg& ret);

    AmRtpStream* getRtpStream() { return stream; }
    AmMediaConnectionFactory* getConnFactory() { return &conn_factory; }

protected:

    ssize_t recv(int sd);
    void recvPacket(int fd) override;

    virtual void onPacket(unsigned char* buf, unsigned int size, sockaddr_storage& addr, struct timeval recvtime);

    void log_rcvd_packet(const char *buffer, int len, struct sockaddr_storage &recv_addr, AmStreamConnection::ConnectionType type);
    void log_sent_packet(const char *buffer, int len, struct sockaddr_storage &send_addr, AmStreamConnection::ConnectionType type);

public:
    int getSrtpCredentialsBySdp(
        const SdpMedia& local_media, const SdpMedia& remote_media,
        string& local_key, srtp_master_keys& remote_keys);

    AmStreamConnection::ConnectionType GetConnectionType(unsigned char* buf, unsigned int size);
    bool isStunMessage(unsigned char* buf, unsigned int size);
    bool isRTPMessage(unsigned char* buf, unsigned int size);
    bool isDTLSMessage(unsigned char* buf, unsigned int size);
    bool isRTCPMessage(unsigned char* buf, unsigned int size);
    bool isZRTPMessage(unsigned char* buf, unsigned int size);

    msg_sensor::packet_type_t streamConnType2sensorPackType(AmStreamConnection::ConnectionType type);

    const char* type2str();

protected:

    Mode mode;

    /** Stream owning this transport */
    AmRtpStream* stream;
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
    
    dtls_client_settings* client_settings;
    dtls_server_settings* server_settings;
    vector<CryptoProfile> allowed_srtp_profiles;
    bool srtp_enable;
    bool dtls_enable;
    bool zrtp_enable;

    vector<SdpCrypto> local_crypto;
    SdpFingerPrint local_dtls_fingerprint;

    AmMutex                     stream_mut;

    map<uint32_t, sockaddr_storage> allowed_ice_addrs;

    trsp_acl media_acl;
};

#endif/*AM_RTP_TRANSPORT_H*/

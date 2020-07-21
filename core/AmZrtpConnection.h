#ifndef AM_ZRTP_CONNECTION_H
#define AM_ZRTP_CONNECTION_H

#ifdef WITH_ZRTP

#include "AmRtpConnection.h"
#include <vector>

extern "C" typedef struct bzrtpSrtpSecrets_struct bzrtpSrtpSecrets_t;

class ZrtpContextSubscriber {
public:
    virtual void zrtpSessionActivated(const bzrtpSrtpSecrets_t *srtpSecrets) = 0;
    virtual int send_zrtp(unsigned char* buffer, unsigned int size){ return 0; }
};

class zrtpContext
{
    void *context;
    uint32_t l_ssrc;
    uint32_t now;
    bool started;
    bool activated;
    std::vector<ZrtpContextSubscriber*> subscribers;
public:
    zrtpContext();
    ~zrtpContext();

    void addSubscriber(ZrtpContextSubscriber* describer);

    string getLocalHash(unsigned int ssrc);
    void setRemoteHash(const string& hash);
    void init(uint8_t type, const std::vector<uint8_t>& values);
    void start();
    bool isStarted() {return started;}
    bool isActivated() {return activated;}

    int onRecvData(uint8_t* data, unsigned int size);
    int onSendData(uint8_t* data, unsigned int size);
    int onActivated(const bzrtpSrtpSecrets_t *srtpSecrets);

    void iterate(uint32_t timestamp);
};

class AmZRTPConnection : public AmStreamConnection, public ZrtpContextSubscriber
{
    zrtpContext* context;
    AmRtpConnection rtp_conn;
    AmRtcpConnection *rtcp_conn;
public:
    AmZRTPConnection(AmMediaTransport* transport, const string& remote_addr, int remote_port);
    ~AmZRTPConnection();

    virtual void handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time);
    virtual bool isUseConnection(ConnectionType type);
    virtual ssize_t send(AmRtpPacket* packet);
    virtual void setPassiveMode(bool p);
    virtual void zrtpSessionActivated(const bzrtpSrtpSecrets_t *srtpSecrets);

    int send(uint8_t* data, unsigned int size);
};

#endif/*WITH_ZRTP*/

#endif/*AM_ZRTP_CONNECTION_H*/

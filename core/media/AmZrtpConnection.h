#ifndef AM_ZRTP_CONNECTION_H
#define AM_ZRTP_CONNECTION_H

#ifdef WITH_ZRTP

#include "AmRtpConnection.h"
#include "sip/types.h"
#include <vector>

extern "C" typedef struct bzrtpSrtpSecrets_struct bzrtpSrtpSecrets_t;

class ZrtpContextSubscriber {
  public:
    virtual void zrtpSessionActivated(srtp_profile_t srtp_profile, const vector<uint8_t> &local_key,
                                      const vector<uint8_t> &remote_key) = 0;
    virtual int  send_zrtp(unsigned char *buffer, unsigned int size) { return 0; }
};

class zrtpContext {
    void                                *context;
    uint32_t                             l_ssrc;
    uint32_t                             now;
    bool                                 inited;
    bool                                 started;
    bool                                 activated;
    CryptoProfile                        srtp_profile;
    string                               remote_hash;
    vector<uint8_t>                      local_key, remote_key;
    std::vector<ZrtpContextSubscriber *> subscribers;


  public:
    zrtpContext();
    ~zrtpContext();

    void addSubscriber(ZrtpContextSubscriber *describer);

    void   createContext(unsigned int ssrc);
    string getLocalHash();
    void   setRemoteHash(const string &hash);
    string getRemoteHash();
    void   setCryptoTypes(uint8_t type, const std::vector<uint8_t> &values);
    void   init();
    void   start();
    bool   isStarted() { return started; }
    bool   isActivated() { return activated; }

    int  onRecvData(uint8_t *data, unsigned int size);
    int  onSendData(uint8_t *data, unsigned int size);
    int  onActivated(const bzrtpSrtpSecrets_t *srtpSecrets);
    bool getZrtpKeysMaterial(CryptoProfile &srtp_profile, vector<uint8_t> &local_key, vector<uint8_t> &remote_key);

    void iterate(uint32_t timestamp);
};

class AmZRTPConnection : public AmStreamConnection {
    zrtpContext    *context;
    AmRtpConnection rtp_conn;

  public:
    AmZRTPConnection(AmMediaTransport *transport, const string &remote_addr, int remote_port, zrtpContext *context);
    virtual ~AmZRTPConnection();

    virtual void handleConnection(uint8_t *data, unsigned int size, struct sockaddr_storage *recv_addr,
                                  struct timeval recv_time);
    virtual void handleSymmetricRtp(struct sockaddr_storage *, struct timeval *)
    { /*symmetric rtp is dsabled for zrtp connection*/ }
    virtual bool    isUseConnection(ConnectionType type);
    virtual ssize_t send(AmRtpPacket *packet);
    virtual void    setPassiveMode(bool p);

    int send(uint8_t *data, unsigned int size);
};

#endif /*WITH_ZRTP*/

#endif /*AM_ZRTP_CONNECTION_H*/

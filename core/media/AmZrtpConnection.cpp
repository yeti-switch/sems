#ifdef WITH_ZRTP

#include <srtp/srtp.h>

#include "AmZrtpConnection.h"
#include "AmMediaTransport.h"
#include "AmRtpStream.h"
extern "C" {
#include <bzrtp/bzrtp.h>
}

static int zrtp_sendData(void *clientData, const uint8_t *packetString, uint16_t packetLength)
{
    zrtpContext *context = (zrtpContext *)clientData;
    return context->onSendData(const_cast<uint8_t *>(packetString), packetLength);
}

static int zrtp_srtpSecretsAvailable(void *clientData, const bzrtpSrtpSecrets_t *srtpSecrets, uint8_t part)
{
    DBG("zrtp srtp secrets available part %d", part);
    return 0;
}

static int zrtp_startSrtpSession(void *clientData, const bzrtpSrtpSecrets_t *srtpSecrets, int32_t verified)
{
    DBG("zrtp start session");
    zrtpContext *context = (zrtpContext *)clientData;
    context->onActivated(srtpSecrets);
    return 0;
}

zrtpContext::zrtpContext()
    : context(0)
    , l_ssrc(0)
    , started(false)
    , activated(false)
{
    timeval tm;
    gettimeofday(&tm, 0);
    now = tm.tv_sec * 1000 + tm.tv_usec / 1000;
}

zrtpContext::~zrtpContext()
{
    if (context) {
        DBG("destroy zrtp context %p for ssrc %d", context, l_ssrc);
        bzrtp_destroyBzrtpContext((bzrtpContext_t *)context, l_ssrc);
    }
}

void zrtpContext::addSubscriber(ZrtpContextSubscriber *subscriber)
{
    subscribers.push_back(subscriber);
}

void zrtpContext::setRemoteHash(const std::string &hash)
{
    if (!context || bzrtp_setPeerHelloHash((bzrtpContext_t *)context, l_ssrc, (uint8_t *)hash.c_str(), hash.size())) {
        throw string("error set peer hello hash");
    } else {
        remote_hash = hash;
        DBG("set zrtp remote hash to zrtp context for ssrc %d", l_ssrc);
    }
}

std::string zrtpContext::getRemoteHash()
{
    return remote_hash;
}

void zrtpContext::init(uint8_t type, const std::vector<uint8_t> &values)
{
    if (!context)
        throw string("zrtp context not created");
    if (!values.empty())
        bzrtp_setSupportedCryptoTypes((bzrtpContext_t *)context, type, (uint8_t *)values.data(), values.size());
}

void zrtpContext::start()
{
    if (!context)
        return;
    else if (!started && bzrtp_startChannelEngine((bzrtpContext_t *)context, l_ssrc))
        throw string("error start zrtp channel engine");
    else
        DBG("start zrtp context for ssrc %d", l_ssrc);
    started = true;
}

std::string zrtpContext::getLocalHash(unsigned int ssrc)
{
    l_ssrc = ssrc;

    if (!context) {
        context = bzrtp_createBzrtpContext();
        bzrtpCallbacks_t callbacks{ .bzrtp_statusMessage               = NULL,
                                    .bzrtp_sendData                    = zrtp_sendData,
                                    .bzrtp_srtpSecretsAvailable        = zrtp_srtpSecretsAvailable,
                                    .bzrtp_startSrtpSession            = zrtp_startSrtpSession,
                                    .bzrtp_contextReadyForExportedKeys = NULL };
        bzrtp_setCallbacks((bzrtpContext_t *)context, &callbacks);
        bzrtp_initBzrtpContext((bzrtpContext_t *)context, ssrc);
        bzrtp_setClientData((bzrtpContext_t *)context, l_ssrc, this);
    }

    string hash(70, 0);
    bzrtp_getSelfHelloHash((bzrtpContext_t *)context, ssrc, (uint8_t *)hash.c_str(), hash.size());
    return hash.c_str() + strlen(ZRTP_VERSION) + 1;
}

int zrtpContext::onRecvData(uint8_t *data, unsigned int size)
{
    if (!context)
        return 0;
    return bzrtp_processMessage((bzrtpContext_t *)context, l_ssrc, data, size);
}

int zrtpContext::onSendData(uint8_t *data, unsigned int size)
{
    for (auto &subscriber : subscribers) {
        subscriber->send_zrtp(data, size);
    }
    return 0;
}

int zrtpContext::onActivated(const bzrtpSrtpSecrets_t *srtpSecrets)
{
    local_key.resize(srtpSecrets->selfSrtpKeyLength + srtpSecrets->selfSrtpSaltLength, 0),
        remote_key.resize(srtpSecrets->peerSrtpKeyLength + srtpSecrets->peerSrtpSaltLength, 0);
    memcpy(local_key.data(), srtpSecrets->selfSrtpKey, srtpSecrets->selfSrtpKeyLength);
    memcpy(local_key.data() + srtpSecrets->selfSrtpKeyLength, srtpSecrets->selfSrtpSalt,
           srtpSecrets->selfSrtpSaltLength);
    memcpy(remote_key.data(), srtpSecrets->peerSrtpKey, srtpSecrets->peerSrtpKeyLength);
    memcpy(remote_key.data() + srtpSecrets->peerSrtpKeyLength, srtpSecrets->peerSrtpSalt,
           srtpSecrets->peerSrtpSaltLength);

    if (srtpSecrets->authTagAlgo == ZRTP_AUTHTAG_HS32) {
        if (srtpSecrets->cipherAlgo == ZRTP_CIPHER_AES3) {
            srtp_profile = static_cast<srtp_profile_t>(CP_AES256_CM_SHA1_32); // TODO(): not supported libsrtp
            //             } else if(srtpSecrets->cipherAlgo == ZRTP_CIPHER_AES2){
            //                 srtp_profile = CP_AES192_CM_SHA1_32;
        } else {
            srtp_profile = srtp_profile_aes128_cm_sha1_32;
        }
    } else if (srtpSecrets->authTagAlgo == ZRTP_AUTHTAG_HS80) {
        if (srtpSecrets->cipherAlgo == ZRTP_CIPHER_AES3) {
            srtp_profile = static_cast<srtp_profile_t>(CP_AES256_CM_SHA1_80); // TODO(): not supported libsrtp
            //             } else if(srtpSecrets->cipherAlgo == ZRTP_CIPHER_AES2){
            //                 srtp_profile = CP_AES192_CM_SHA1_80;
        } else {
            srtp_profile = srtp_profile_aes128_cm_sha1_80;
        }
    } else {
        CLASS_ERROR("encryption methods with keys derived using ZRTP are not supported");
        return 1;
    }
    activated = true;
    for (auto &subscriber : subscribers) {
        subscriber->zrtpSessionActivated((srtp_profile_t)srtp_profile, local_key, remote_key);
    }
    return 0;
}

bool zrtpContext::getZrtpKeysMaterial(srtp_profile_t &srtpprofile, vector<uint8_t> &lkey, vector<uint8_t> &rkey)
{
    if (!activated)
        return false;
    srtpprofile = srtp_profile;
    lkey        = local_key;
    rkey        = remote_key;
    return true;
}


void zrtpContext::iterate(uint32_t timestamp)
{
    if (!context)
        return;
    timeval tm;
    gettimeofday(&tm, 0);
    uint32_t last = tm.tv_sec * 1000 + tm.tv_usec / 1000;
    bzrtp_iterate((bzrtpContext_t *)context, l_ssrc, last - now);
    now = last;
}

AmZRTPConnection::AmZRTPConnection(AmMediaTransport *transport, const string &remote_addr, int remote_port,
                                   zrtpContext *context)
    : AmStreamConnection(transport, remote_addr, remote_port, AmStreamConnection::ZRTP_CONN)
    , context(context)
    , rtp_conn(this, remote_addr, remote_port)
{
}

AmZRTPConnection::~AmZRTPConnection() {}

bool AmZRTPConnection::isUseConnection(AmStreamConnection::ConnectionType type)
{
    return !context->isActivated() && (type == AmStreamConnection::RTP_CONN || type == AmStreamConnection::ZRTP_CONN);
}

void AmZRTPConnection::handleConnection(uint8_t *data, unsigned int size, struct sockaddr_storage *recv_addr,
                                        struct timeval recv_time)
{
    if (getTransport()->isZRTPMessage(data, size)) {
        context->onRecvData(data, size);
    } else if (getTransport()->isRTPMessage(data, size)) {
        rtp_conn.process_packet(data, size, recv_addr, recv_time);
    }
}

void AmZRTPConnection::setPassiveMode(bool p)
{
    rtp_conn.setPassiveMode(p);
    AmStreamConnection::setPassiveMode(p);
}

ssize_t AmZRTPConnection::send(AmRtpPacket *packet)
{
    if (!context->isActivated()) {
        context->iterate(packet->timestamp);
        return rtp_conn.send(packet);
    }
    return 0;
}

int AmZRTPConnection::send(uint8_t *data, unsigned int size)
{
    AmRtpPacket packet;
    packet.compile_raw(data, size);
    return AmStreamConnection::send(&packet);
}


#endif /*WITH_ZRTP*/

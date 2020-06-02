#ifdef WITH_ZRTP

#include "AmZrtpConnection.h"
#include "AmMediaTransport.h"
#include "AmRtpStream.h"
extern "C" {
#include <bzrtp/bzrtp.h>
}

static int zrtp_sendData(void *clientData, const uint8_t *packetString, uint16_t packetLength)
{
    zrtpContext* context = (zrtpContext*)clientData;
    return context->onSendData(const_cast<uint8_t*>(packetString), packetLength);
}

static int zrtp_srtpSecretsAvailable(void *clientData, const bzrtpSrtpSecrets_t *srtpSecrets, uint8_t part)
{
    DBG("zrtp srtp secrets available part %d", part);
    return 0;
}

static int zrtp_startSrtpSession(void *clientData, const bzrtpSrtpSecrets_t *srtpSecrets, int32_t verified)
{
    DBG("zrtp start session");
    zrtpContext* context = (zrtpContext*)clientData;
    context->onActivated(srtpSecrets);
    return 0;
}

zrtpContext::zrtpContext()
: l_ssrc(0), context(0)
, activated(false), started(false)
{
    timeval tm;
    gettimeofday(&tm, 0);
    now = tm.tv_sec*1000 + tm.tv_usec/1000;
}

zrtpContext::~zrtpContext()
{
    if(context) {
        DBG("destroy zrtp context %p for ssrc %d", context, l_ssrc);
        bzrtp_destroyBzrtpContext((bzrtpContext_t*)context, l_ssrc);
    }
}

void zrtpContext::addSubscriber(ZrtpContextSubscriber* subscriber)
{
    subscribers.push_back(subscriber);
}

void zrtpContext::setRemoteHash(const std::string& hash)
{
    if(!context || bzrtp_setPeerHelloHash((bzrtpContext_t*)context, l_ssrc, (uint8_t*)hash.c_str(), hash.size()))
        throw string("error set peer hello hash");
    else
        DBG("set zrtp remote hash to zrtp context for ssrc %d", l_ssrc);
}

void zrtpContext::init(uint8_t type, const std::vector<uint8_t>& values)
{
    if(!context)
        throw string("zrtp context not created");
    if(!values.empty())
        bzrtp_setSupportedCryptoTypes((bzrtpContext_t*)context, type, (uint8_t*)values.data(), values.size());
}

void zrtpContext::start()
{
    if(!context) return;
    else if(!started && bzrtp_startChannelEngine((bzrtpContext_t*)context, l_ssrc))
        throw string("error start zrtp channel engine");
    else
        DBG("start zrtp context for ssrc %d", l_ssrc);
    started = true;
}

std::string zrtpContext::getLocalHash(unsigned int ssrc)
{
    l_ssrc = ssrc;

    if(!context) {
        context = bzrtp_createBzrtpContext();
        bzrtpCallbacks_t callbacks{
            .bzrtp_statusMessage = NULL,
                    .bzrtp_sendData = zrtp_sendData,
                    .bzrtp_srtpSecretsAvailable = zrtp_srtpSecretsAvailable,
                    .bzrtp_startSrtpSession = zrtp_startSrtpSession,
                    .bzrtp_contextReadyForExportedKeys = NULL
        };
        bzrtp_setCallbacks((bzrtpContext_t*)context, &callbacks);
        bzrtp_initBzrtpContext((bzrtpContext_t*)context, ssrc);
        bzrtp_setClientData((bzrtpContext_t*)context, l_ssrc, this);
    }

    string hash(70, 0);
    bzrtp_getSelfHelloHash((bzrtpContext_t*)context, ssrc, (uint8_t*)hash.c_str(), hash.size());
    return hash.c_str() + strlen(ZRTP_VERSION) + 1;
}

int zrtpContext::onRecvData(uint8_t* data, unsigned int size)
{
    if(!context) return 0;
    return bzrtp_processMessage((bzrtpContext_t*)context, l_ssrc, data, size);
}

int zrtpContext::onSendData(uint8_t* data, unsigned int size)
{
    for(auto& subscriber : subscribers) {
        subscriber->send_zrtp(data, size);
    }
    return 0;
}

int zrtpContext::onActivated(const bzrtpSrtpSecrets_t *srtpSecrets)
{
    activated = true;
    for(auto& subscriber : subscribers) {
        subscriber->zrtpSessionActivated(srtpSecrets);
    }
    return 0;
}

void zrtpContext::iterate(uint32_t timestamp)
{
    if(!context) return;
    timeval tm;
    gettimeofday(&tm, 0);
    uint32_t last = tm.tv_sec*1000 + tm.tv_usec/1000;
    bzrtp_iterate((bzrtpContext_t*)context, l_ssrc, last - now);
    now = last;
}

AmZRTPConnection::AmZRTPConnection(AmMediaTransport* transport, const string& remote_addr, int remote_port)
: AmStreamConnection(transport, remote_addr, remote_port, AmStreamConnection::ZRTP_CONN)
, context(transport->getRtpStream()->getZrtpContext())
, rtp_conn(this, remote_addr, remote_port)
{
    rtcp_conn = new AmRtcpConnection(transport, remote_addr, remote_port);
    transport->addConnection(rtcp_conn);
    context->addSubscriber(this);
}

AmZRTPConnection::~AmZRTPConnection()
{
}

bool AmZRTPConnection::isUseConnection(AmStreamConnection::ConnectionType type)
{
    return !context->isActivated() && (type == AmStreamConnection::RTP_CONN || type == AmStreamConnection::ZRTP_CONN);
}

void AmZRTPConnection::handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time)
{
    handleSymmetricRtp(recv_addr, &recv_time);
    if(getTransport()->isZRTPMessage(data, size)) {
        context->onRecvData(data, size);
    } else if(getTransport()->isRTPMessage(data, size)) {
        rtp_conn.handleConnection(data, size, recv_addr, recv_time);
    }
}

void AmZRTPConnection::zrtpSessionActivated(const bzrtpSrtpSecrets_t *srtpSecrets)
{
    getTransport()->removeConnection(rtcp_conn);
}

ssize_t AmZRTPConnection::send(AmRtpPacket* packet)
{
    if(!context->isActivated()) {
        context->iterate(packet->timestamp);
        return rtp_conn.send(packet);
    }
    return 0;
}

int AmZRTPConnection::send(uint8_t* data, unsigned int size)
{
    AmRtpPacket packet;
    packet.compile_raw(data, size);
    return AmStreamConnection::send(&packet);
}


#endif/*WITH_ZRTP*/

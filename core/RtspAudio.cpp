#include "AmEventDispatcher.h"
#include "AmSessionContainer.h"
#include "AmSession.h"
#include "AmAudio.h"
#include "AmUtils.h"

#include "RtspClient.h"
#include "RtspAudio.h"


using std::string;
using namespace Rtsp;

static const int RTP_TIMEOUT_SEC =  1;

RtspAudio::RtspAudio(AmSession* _s, const string &uri)
  : AmRtpAudio(_s, RtspClient::instance()->getRtpInterface()),
    agent(RtspClient::instance()),
    md(0),
    streamid(-1),
    state(Ready)
{
    id = agent->addStream(*this);

    AmRtpStream::setRtpTimeout(RTP_TIMEOUT_SEC);
    sockaddr_storage ss;
    am_inet_pton(agent->localMediaIP().c_str(), &ss);
    AmRtpAudio::setLocalIP(ss.ss_family == AF_INET ? AT_V4 : AT_V6);

    open(uri);
}


RtspAudio::~RtspAudio()
{
    DBG("####### RtspAudio::~RtspAudio()");

    teardown();

    agent->removeStream(id);
}


void RtspAudio::close()
{
   teardown();
}


void RtspAudio::open(const string& _uri)
{
    DBG("####### %s: '%s'", __func__, _uri.c_str());

    teardown();

    uri = _uri;

    describe();
}

/**
* URI MUST be absolute "{rtsp://}{domain[:port]/}{[path]}[/streamid=N]"
**/
void RtspAudio::teardown()
{
    if (state == Ready)
        return;

    if(state == Playing) {
        last_sent_cseq = agent->RtspRequest(RtspMsg(TEARDOWN, uri + "/streamid=" + int2str(streamid), id));
    }

    state = Ready;
}


void RtspAudio::describe()
{
    state = Progress;
    last_sent_cseq = agent->RtspRequest(RtspMsg(DESCRIBE, uri, id));
}


void RtspAudio::setup(int l_port)
    {
    struct RtspMsg msg = RtspMsg(SETUP, uri, id) ;

    msg.header[H_Transport] = "RTP/AVP;unicast;client_port=" + int2str(l_port)+"-"+int2str(l_port + 1);

    last_sent_cseq = agent->RtspRequest(msg);
}


void RtspAudio::rtsp_play(const RtspMsg &msg)
{
    if (!uri.length()) {
        ERROR("%s Uri must be set by setup()", __func__);
        return;
    }

    try {
        initRtpAudio(msg.r_rtp_port);

        last_sent_cseq = agent->RtspRequest(RtspMsg(PLAY, uri, id));

        play();

    } catch (AmSession::Exception &e) {
        DBG("####### catched AmSession::Exception(%d,%s)", e.code, e.reason.c_str());
    }
}

void RtspAudio::initIP4Transport()
{
    if(!ip4_transports.empty()) {
        return;
    }

    AmMediaTransport *rtp = new AmMediaTransport(this, RtspClient::instance()->getRtpInterface(), RtspClient::instance()->getRtpProtoId(), RTP_TRANSPORT),
                   *rtcp = new AmMediaTransport(this, RtspClient::instance()->getRtpInterface(), RtspClient::instance()->getRtpProtoId(), RTCP_TRANSPORT);
    ip4_transports.push_back(rtp);
    ip4_transports.push_back(rtcp);
    calcRtpPorts(rtp, rtcp);
    rtp->setTransportType(RTP_TRANSPORT);
    rtcp->setTransportType(RTCP_TRANSPORT);
}

void RtspAudio::initIP6Transport()
{
    throw string ("not supported yet");
}

bool RtspAudio::initSdpAnswer()
{
    setLocalIP(AmConfig.getMediaProtoInfo(RtspClient::instance()->getRtpInterface(),RtspClient::instance()->getRtpProtoId()).type_ip);
    if(offer.media.empty()) {
        ERROR("empty offer");
        return false;
    }

    SdpMedia& offer_media = offer.media.front();
    if(offer_media.type != MT_AUDIO || offer_media.transport != TP_RTPAVP) {
        ERROR("unsupported media format");
        return false;
    }

    if(offer_media.port == 0) {
        ERROR("offer port is 0");
        return false;
    }

    answer.version = 0;
    answer.origin.user = AmConfig.sdp_origin;
    answer.sessionName = AmConfig.sdp_session_name;
    answer.conn.network = NT_IN;
    answer.conn.addrType = offer.conn.address.empty() ? AT_V4 : offer.conn.addrType;
    answer.conn.address = agent->localMediaIP();

    answer.media.clear();
    answer.media.push_back(SdpMedia());

    SdpMedia &answer_media = answer.media.back();

    AmRtpAudio::getSdpAnswer(0, offer_media, answer_media);

    if(answer_media.payloads.empty()) {
        ERROR("no compatible payload");
        return false;
    }

    return true;
}

void RtspAudio::initRtpAudio(unsigned short int  r_rtp_port)
{
    if (!offer.media.size()) {
        ERROR("******* RtspAudio::initRtpAudio_by_transport_hdr() offer.media is empty");
        return;
    }

    if (!offer.media[0].port && r_rtp_port) // Got SDP m=audio 0, set port from header Transport: server_port=xxxxx
        offer.media[0].port = r_rtp_port;

    if(!initSdpAnswer()) {
        ERROR("failed to init SDP answer");
        return;
    }

    AmRtpAudio::init(answer, offer);
    resumeReceiving();
}


int RtspAudio::initRtpAudio_by_sdp(const char *sdp_msg)
{
    string  sdp_body;

    offer.clear();
    offer.parse(sdp_msg);

    offer.print(sdp_body);

    //INFO("******* SDP offer body:\n%s", sdp_body.c_str());

    if(!initSdpAnswer()) {
        ERROR("failed to init SDP answer");
        throw AmSession::Exception(488, "failed to init SDP answer");
    }

    answer.print(sdp_body);

    //INFO("******* SDP answer body:\n%s", sdp_body.c_str());

    AmRtpAudio::init(answer, offer);
    resumeReceiving();

    return getLocalPort();
}


void RtspAudio::play()
{
    state = Playing;
    session->setOutput(this);
}


void RtspAudio::onRtpTimeout()
{
    DBG("onRtpTimeout() id: %ld, streamid: %d, uri: %s",
        id,streamid,uri.c_str());
    if (state == Playing)
        session->postEvent(new AmAudioEvent(AmAudioEvent::noAudio));

    state = Ready;
}

void RtspAudio::onMaxRtpTimeReached()
{
    DBG("onMaxRtpTimeReached() id: %ld, streamid: %d, uri: %s",
        id,streamid,uri.c_str());
    if (state == Playing)
        session->postEvent(new AmAudioEvent(AmAudioEvent::noAudio));

    state = Ready;
}

void RtspAudio::onRtspPlayNotify(const RtspMsg & msg) {
    DBG("onRtspPlayNotify() id: %ld, streamid: %d, rtptime: %u, uri: %s",
        id,streamid, msg.rtptime, uri.c_str());

    if(msg.rtptime) {
        setMaxRtpTime(msg.rtptime);
        return;
    }

    state = Ready;
    session->postEvent(new AmAudioEvent(AmAudioEvent::noAudio));
}


void RtspAudio::onRtspMessage(const RtspMsg &msg)
{
    RtspMsg::HeaderIterator it;

    if(msg.type == RTSP_REPLY) {
        if(last_sent_cseq > msg.cseq) {
            DBG("onRtspMessage(): ignore reply with obsolete cseq: %d (last_sent_cseq: %d)",
                msg.cseq,last_sent_cseq);
            return;
        }
        if(state == Ready) {
            DBG("onRtspMessage(): ignore reply received in Ready state");
            return;
        }
    }

    if (msg.code != 200) {
        session->postEvent(new RtspNoFileEvent(uri));
        return;
    }

    /** Check ContentType header after DESCRIBE request */
    it = msg.header.find(H_ContentType);

    if (it != msg.header.end() && strstr(it->second.c_str(), "application/sdp")) {
        try {
            int l_port = initRtpAudio_by_sdp(msg.body.c_str());
            setup(l_port);

        } catch (AmSession::Exception &e) {
            INFO("####### catched AmSession::Exception(%d,%s)", e.code, e.reason.c_str());
        }
    }

    it  = msg.header.find(H_RTP_Info);
    if (it != msg.header.end())
        streamid = msg.streamid;

    /** Check Transport header after SETUP request */
    it  = msg.header.find(H_Transport);
    if (it != msg.header.end())
        rtsp_play(msg);
}

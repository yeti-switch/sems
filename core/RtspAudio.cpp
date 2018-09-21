#include "AmEventDispatcher.h"
#include "AmSessionContainer.h"
#include "AmSession.h"
#include "AmAudio.h"
#include "AmConfig.h"

#include "RtspClient.h"
#include "RtspAudio.h"


using std::string;
using namespace Rtsp;

static const int RTP_TIMEOUT_SEC =  1;


RtspAudio::RtspAudio(AmSession* _s, const string &uri)
    :  streamid(-1), md(0), session(_s), agent(RtspClient::instance()),
      AmRtpAudio(_s, RtspClient::instance()->getRtpInterface(), RtspClient::instance()->getRtpAddr())
{
    id = agent->addStream(*this);

    AmRtpStream::setRtpTimeout(RTP_TIMEOUT_SEC);
    AmRtpAudio::setLocalIP(agent->localMediaIP());

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
    if (state != Playing)
        return;

    agent->RtspRequest(RtspMsg(TEARDOWN, uri + "/streamid=" + int2str(streamid), id));

    state = Ready;
}


void RtspAudio::describe()
{
    agent->RtspRequest(RtspMsg(DESCRIBE, uri, id));
}


void RtspAudio::setup(int l_port)
{
    struct RtspMsg msg = RtspMsg(SETUP, uri, id) ;

    msg.header[H_Transport] = "RTP/AVP;unicast;client_port=" + int2str(l_port)+"-"+int2str(l_port + 1);

    agent->RtspRequest(msg);
}


void RtspAudio::rtsp_play(const RtspMsg &msg)
{
    if (!uri.length()) {
        ERROR("%s Uri must be set by setup()", __func__);
        return;
    }

    try {
        initRtpAudio(msg.r_rtp_port);

        agent->RtspRequest(RtspMsg(PLAY, uri, id));

        play();

    } catch (AmSession::Exception &e) {
        DBG("####### catched AmSession::Exception(%d,%s)", e.code, e.reason.c_str());
    }
}


void RtspAudio::initRtpAudio(unsigned short int  r_rtp_port)
{
    if (!offer.media.size()) {
        ERROR("******* RtspAudio::initRtpAudio_by_transport_hdr() offer.media is empty");
        return;
    }

    if (!offer.media[0].port && r_rtp_port) // Got SDP m=audio 0, set port from header Transport: server_port=xxxxx
        offer.media[0].port = r_rtp_port;

    session->getSdpAnswer(offer, answer);
    AmRtpAudio::getSdpAnswer(0, answer.media[0], offer.media[0]);
    AmRtpAudio::init(answer, offer);
}


int RtspAudio::initRtpAudio_by_sdp(const char *sdp_msg)
{
    string  sdp_body;

    offer.clear();
    offer.parse(sdp_msg);

    offer.print(sdp_body);

    //INFO("******* SDP offer body:\n%s\n", sdp_body.c_str());

    session->getSdpAnswer(offer, answer);

    answer.print(sdp_body);

    //INFO("******* SDP answer body:\n%s\n", sdp_body.c_str());

    if(offer.media[0].port) // Got SDP m=audio <port>
    {
        AmRtpAudio::getSdpAnswer(0, answer.media[0], offer.media[0]);
        AmRtpAudio::init(answer, offer);
    }

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


void RtspAudio::onRtspPlayNotify(const RtspMsg &msg) {
    DBG("onRtspPlayNotify() id: %ld, streamid: %d, uri: %s",
        id,streamid,uri.c_str());
    state = Ready;
    session->postEvent(new AmAudioEvent(AmAudioEvent::noAudio));
}


void RtspAudio::onRtspMessage(const RtspMsg &msg)
{
    RtspMsg::HeaderIterator it;

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

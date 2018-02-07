#include "AmEventDispatcher.h"
#include "AmSession.h"
#include "AmAudio.h"
#include "AmConfig.h"

#include "RtspClient.h"
#include "RtspAudio.h"


using std::string;


static const int RTP_TIMEOUT_SEC =  1;


RtspAudio::RtspAudio(AmSession* _s, const string &uri)
    :  session(_s), AmRtpAudio(_s, RtspClient::instance()->getRtpInterface() )
{
    agent = RtspClient::instance();

    AmRtpStream::setRtpTimeout(RTP_TIMEOUT_SEC);
    AmRtpAudio::setLocalIP(agent->localMediaIP());

    open(uri);
}


RtspAudio::~RtspAudio()
{
    DBG("####### RtspAudio::~RtspAudio()");

    close();
}



void RtspAudio::open(const string& uri)
{
    DBG("####### %s: '%s'", __func__, uri.c_str());

    agent->addStream(*this, uri);
}


void inline RtspAudio::close()
{
   DBG("####### %s", __func__);

    agent->removeStream(*this);
}


#if 0
void RtspAudio::sendEvent(AmAudioEvent::EventType type)
{
    INFO("####### %s", __func__);

    if(type == AmAudioEvent::noAudio)
        AmEventDispatcher::instance()->post(session->getLocalTag(),
            new RtspNoAudioEvent());
    else
        AmEventDispatcher::instance()->post(session->getLocalTag(),
            new AmAudioEvent(type) );

}
#endif


void RtspAudio::initRtpAudio(unsigned short int  r_rtp_port)
{
    if(!offer.media.size())
    {
        ERROR("******* RtspAudio::initRtpAudio_by_transport_hdr() offer.media is empty");
        return;
    }

    if(!offer.media[0].port && r_rtp_port) // Got SDP m=audio 0, set port from header Transport: server_port=xxxxx
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
    session->setOutput(this);
    //AmMediaProcessor::instance()->addSession(session, session->getCallgroup());
}

void RtspAudio::onRtpTimeout() {
    close();
    session->postEvent(new AmAudioEvent(AmAudioEvent::noAudio));
}

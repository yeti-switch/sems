#pragma once

#include "AmSession.h"


class RtspClient;

class RtspAudio  :   public AmRtpAudio
{
        RtspClient          *agent;
        AmSdp               offer, answer;
        /** Session owning this stream */
        AmSession           *session;
  public:
        RtspAudio(AmSession* _s, const string &uri);
        ~RtspAudio();


        const string& getLocalTag() { return session->getLocalTag();}
        //void 	sendEvent(AmAudioEvent::EventType type);
        void    open(const string& uri);
        void    close();
        void    initRtpAudio(unsigned short int r_rtp_port);
        int     initRtpAudio_by_sdp(const char *sdp_msg);
        void    play();
};

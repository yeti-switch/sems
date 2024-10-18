#pragma once

#include "AmSession.h"
#include "RtspConnection.h"

using namespace Rtsp;

class RtspClient;

using Rtsp::RtspMsg;
using Rtsp::RtspSession;

class RtspAudio : public AmRtpAudio
{
    typedef enum {
        Ready = 0,
        Progress,
        Playing
    } State;

        uint64_t            id;             /** unique RtspAudio ID */
        RtspClient          *agent;

        //int                 md;             /** media server descriptor */
        uint32_t            ssrc;
        int                 streamid;       /** streamid from media server RTP-Info header */
        int                 last_sent_cseq; /** cseq of the last sent request */
        uint64_t            start_progress_time; /** opening time **/

        State               state;
        string              uri;
        AmSdp               offer, answer;
        // RtspMsg             req;

    private:
        void    initIP4Transport() override;
        void    initIP6Transport() override;
        bool    initSdpAnswer();
        void    initRtpAudio(unsigned short int r_rtp_port);
        int     initRtpAudio_by_sdp(const char *sdp_msg);
        void    describe();
        void    teardown();
        void    setup(int l_port);
        void    play();
        void    rtsp_play(const RtspMsg &msg);

        void    onRtpTimeout() override;
        void    onMaxRtpTimeReached() override;

    public:
        RtspAudio(AmSession* _s, const string &uri);
        ~RtspAudio();

        uint32_t getStreamSSRC() { return ssrc; }
        int     getStreamID() { return streamid; }
        bool    isPlaying()    { return state == Playing; }

        void    close() override;
        void    open(const string& uri);
        void    checkState(uint64_t timeout);
        void    onRtspMessage(const RtspMsg &msg);
        void    onRtspPlayNotify(const RtspMsg &msg);

        bool isZrtpEnabled() override { return false; }
};

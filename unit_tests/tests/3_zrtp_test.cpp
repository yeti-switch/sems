#include "../Config.h"
#include "../WorkersManager.h"
#include "../TestPayloadProvider.h"
#include <AmSessionContainer.h>
#include <AmMediaProcessor.h>
#include <AmAdvancedAudio.h>
#include <AmRtpReceiver.h>
#include <AmSipDialog.h>
#include <AmSession.h>
#include <gtest/gtest.h>
#include <string>

#define OFFER  1
#define ANSWER 2

class ZRTPSession;

class ZRTPAudio : public AmNullAudio
{
    ZRTPSession* session_;
public:
    ZRTPAudio(ZRTPSession* session)
    : AmNullAudio(test_config::instance()->stress_session_duration, test_config::instance()->stress_session_duration)
    , session_(session){}
    ~ZRTPAudio(){}

    int get(unsigned long long system_ts, unsigned char * buffer, int output_sample_rate, unsigned int nb_samples) override;
};


class ZRTPSession : public AmSession, public ZrtpContextSubscriber
{
public:
    AmSdp local;
    AmSdp* remote;
    ZRTPAudio audio;
    TestPayloadProvider pl_prov;
    int OAtype;
    AmCondition<bool> started;
    AmCondition<bool> zrtp_activated;

    ZRTPSession(const string& remote_uri, int OA)
    : OAtype(OA), remote(0), audio(this)
    , started(false), zrtp_activated(false)
    {
        srtp_init();
        RTPStream()->setMonitorRTPTimeout(false);
        RTPStream()->setPayloadProvider(&pl_prov);
        RTPStream()->getZrtpContext()->addSubscriber(this);

        dlg->setRemoteUri(remote_uri);
        setLocalTag();
        setZrtpEnabled(true);
    }
    ~ZRTPSession()
    {
        srtp_shutdown();
    }

    void setRemoteSdp(AmSdp* remoteSdp)
    {
        remote = remoteSdp;
    }

    AmSdp* getLocalSdp()
    {
        return &local;
    }

    int init()
    {
        setInOut(&audio, &audio);
        return RTPStream()->init(local, *remote);
    }

    virtual void zrtpSessionActivated(const bzrtpSrtpSecrets_t*) override
    {
        zrtp_activated.set(true);
        setStopped();
    };
    
    virtual void onStart() override
    {
        AmSessionContainer::instance()->addSession(getLocalTag(), this);
        started.set(true);
        RTPStream()->resumeReceiving();
        startMediaProcessing();
    }

    void wait_started() {
        started.wait_for();
    }
};

int ZRTPAudio::get(unsigned long long system_ts, unsigned char * buffer, int output_sample_rate, unsigned int nb_samples)
{
    int ret = AmNullAudio::get(system_ts, buffer, output_sample_rate, nb_samples);
    if(ret < 0) {
        AmMediaProcessor::instance()->clearSession(session_);
        return -1;
    }
    return ret;
}

class ZRTPTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        AmMediaProcessor::instance()->init();
        AmRtpReceiver::instance()->start();
    }
    void TearDown() override
    {
        AmRtpReceiver::dispose();
        AmMediaProcessor::dispose();
    }
};


TEST_F(ZRTPTest, SingleTest) {
    string error;
    try {
        unsigned int idx = AmConfig.sip_if_names[test_config::instance()->signalling_interface];
        string ip;
        if(AmConfig.sip_ifs[idx].proto_info.size()) ip = AmConfig.sip_ifs[idx].proto_info[0]->getIP();
        ASSERT_FALSE(ip.empty());
        ip.insert(0, "sip:");

        ZRTPSession sessionA(ip, OFFER), sessionB(ip, ANSWER);
        sessionA.setMediaTransport(TP_RTPAVP);
        sessionB.setMediaType(MT_AUDIO);
        sessionA.getSdpOffer(sessionA.local);
        EXPECT_EQ(sessionA.local.media.size(), 1);

        sessionB.setMediaTransport(TP_RTPAVP);
        sessionB.setMediaType(MT_AUDIO);
        GTEST_ASSERT_NE(sessionA.local.media.size(), 0);
        sessionB.getSdpAnswer(sessionA.local, sessionB.local);
        GTEST_ASSERT_EQ(sessionB.local.media.size(), 1);
        string sdp;
        sessionB.local.print(sdp);

        sessionA.setRemoteSdp(sessionB.getLocalSdp());
        sessionB.setRemoteSdp(sessionA.getLocalSdp());
        GTEST_ASSERT_EQ(sessionA.init(), 0);
        GTEST_ASSERT_EQ(sessionB.init(), 0);
        sessionA.start();
        sessionB.start();
        sessionA.wait_started();
        sessionB.wait_started();
        while(AmSession::getSessionNum()) { usleep(100); }
        EXPECT_TRUE(sessionA.zrtp_activated.get());
        EXPECT_TRUE(sessionB.zrtp_activated.get());
    } catch(const AmSession::Exception& except) {
        error = except.reason;
    } catch(const string& reason) {
        error = reason.c_str();
    }

    if(!error.empty()) FAIL() << "Exception - " << error.c_str() << std::endl;
}

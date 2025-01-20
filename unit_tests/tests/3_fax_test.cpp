#include "../Config.h"
#include "../WorkersManager.h"
#include "../TestPayloadProvider.h"
#include <AmSessionContainer.h>
#include <AmMediaProcessor.h>
#include <AmStunProcessor.h>
#include <AmFaxImage.h>
#include <AmRtpReceiver.h>
#include <AmSipDialog.h>
#include <AmSession.h>
#include <gtest/gtest.h>
#include <string>

#define OFFER  1
#define ANSWER 2
#define TIFF_FILE_OFFER  "./unit_tests/q.tiff"
#define TIFF_FILE_ANSWER "./unit_tests/q1.tiff"

class FaxSession : public AmSession
{
public:
    AmSdp local;
    AmSdp* remote;
    FaxAudioImage* audio;
    FaxT38Image* t38;
    TestPayloadProvider pl_prov;
    int OAtype;
    AmCondition<bool> started;
    bool fax_success;

    FaxSession(const string& remote_uri, int OA)
    : remote(0), OAtype(OA), started(false), fax_success(false)
    {
        RTPStream()->setMonitorRTPTimeout(false);

        audio = new FaxAudioImage(this, (OA == OFFER) ? TIFF_FILE_OFFER : TIFF_FILE_ANSWER, (OA == OFFER), 0);
        t38 = new FaxT38Image(this, (OA == OFFER) ? TIFF_FILE_OFFER : TIFF_FILE_ANSWER, (OA == OFFER), 0);
        inc_ref(t38);
        audio->init_tone_fax();
        dlg->setRemoteUri(remote_uri);
        setLocalTag();
    }
    ~FaxSession()
    {
        delete audio;
        dec_ref(t38);
    }

    void process(AmEvent* ev) override
    {
        FaxCompleteEvent* fax_ev = dynamic_cast<FaxCompleteEvent*>(ev);
        if(fax_ev){
            fax_success = fax_ev->m_isSuccess;
            RTPStream()->stopReceiving();
            AmMediaProcessor::instance()->clearSession(t38);
            AmMediaProcessor::instance()->clearSession(this);
            while(t38->isProcessingMedia() || isProcessingMedia()) { sleep(1); }
            setStopped();
            return;
        }

        AmSession::process(ev);
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
        setInOut(audio, audio);
        return RTPStream()->init(local, *remote, true, false);
    }

    virtual void onStart() override
    {
        AmSessionContainer::instance()->addSession(getLocalTag(), this);
        started.set(true);
        RTPStream()->resumeReceiving();
        if(local.media[RTPStream()->getSdpMediaIndex()].type == MT_IMAGE) {
            AmMediaProcessor::instance()->addSession(t38, callgroup);
        } else {
            startMediaProcessing();
        }
    }

    void checkData() {
        EXPECT_TRUE(fax_success);
        remove(TIFF_FILE_ANSWER);
    }

    void wait_started() {
        started.wait_for();
    }
};

class FaxTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        AmMediaProcessor::instance()->init();
        AmRtpReceiver::instance()->start();
        stun_processor::instance()->start();
    }
    void TearDown() override
    {
        AmRtpReceiver::dispose();
        AmMediaProcessor::dispose();
        stun_processor::dispose();
    }
};

TEST_F(FaxTest, SingleT38Test) {
    string error;
    try {
        unsigned int idx = AmConfig.sip_if_names[test_config::instance()->signalling_interface];
        string ip;
        if(AmConfig.sip_ifs[idx].proto_info.size()) ip = AmConfig.sip_ifs[idx].proto_info[0]->getIP();
        ASSERT_FALSE(ip.empty());
        ip.insert(0, "sip:");

        FaxSession sessionA(ip, OFFER), sessionB(ip, ANSWER);
        t38_option options;

        sessionA.setMediaTransport(TP_UDPTL);
        sessionA.setMediaType(MT_IMAGE);
        sessionA.getSdpOffer(sessionA.local);
        GTEST_ASSERT_EQ(sessionA.local.media.size(), 1);
        options.negotiateT38Options(sessionA.local.media[sessionA.RTPStream()->getSdpMediaIndex()].attributes);
        sessionA.t38->setOptions(options);

        sessionB.setMediaTransport(TP_UDPTL);
        sessionB.setMediaType(MT_IMAGE);
        GTEST_ASSERT_NE(sessionA.local.media.size(), 0);
        sessionB.getSdpAnswer(sessionA.local, sessionB.local);
        GTEST_ASSERT_EQ(sessionB.local.media.size(), 1);
        options.negotiateT38Options(sessionB.local.media[sessionA.RTPStream()->getSdpMediaIndex()].attributes);
        sessionB.t38->setOptions(options);

        sessionA.setRemoteSdp(sessionB.getLocalSdp());
        sessionB.setRemoteSdp(sessionA.getLocalSdp());
        EXPECT_EQ(sessionA.init(), 0);
        EXPECT_EQ(sessionB.init(), 0);
        sessionA.start();
        sessionB.start();
        sessionA.wait_started();
        sessionB.wait_started();
        while(AmSession::getSessionNum()) { usleep(100); }
        sessionA.checkData();
        sessionB.checkData();
    } catch(const AmSession::Exception& except) {
        error = except.reason;
    } catch(const string& reason) {
        error = reason.c_str();
    }

    if(!error.empty()) FAIL() << "Exception - " << error.c_str() << std::endl;
}

TEST_F(FaxTest, IceT38Test) {
    string error;
    try {
        unsigned int idx = AmConfig.sip_if_names[test_config::instance()->signalling_interface];
        string ip;
        if(AmConfig.sip_ifs[idx].proto_info.size()) ip = AmConfig.sip_ifs[idx].proto_info[0]->getIP();
        ASSERT_FALSE(ip.empty());
        ip.insert(0, "sip:");

        FaxSession sessionA(ip, OFFER), sessionB(ip, ANSWER);
        t38_option options;

        sessionA.setMediaTransport(TP_UDPTL);
        sessionA.setMediaType(MT_IMAGE);
        sessionA.useIceMediaStream();
        sessionA.getSdpOffer(sessionA.local);
        GTEST_ASSERT_EQ(sessionA.local.media.size(), 1);
        options.negotiateT38Options(sessionA.local.media[sessionA.RTPStream()->getSdpMediaIndex()].attributes);
        sessionA.t38->setOptions(options);

        sessionB.setMediaTransport(TP_UDPTL);
        sessionB.setMediaType(MT_IMAGE);
        GTEST_ASSERT_NE(sessionA.local.media.size(), 0);
        sessionB.useIceMediaStream();
        sessionB.getSdpAnswer(sessionA.local, sessionB.local);
        GTEST_ASSERT_EQ(sessionB.local.media.size(), 1);
        options.negotiateT38Options(sessionB.local.media[sessionA.RTPStream()->getSdpMediaIndex()].attributes);
        sessionB.t38->setOptions(options);

        sessionA.setRemoteSdp(sessionB.getLocalSdp());
        sessionB.setRemoteSdp(sessionA.getLocalSdp());
        EXPECT_EQ(sessionA.init(), 0);
        EXPECT_EQ(sessionB.init(), 0);
        sessionA.start();
        sessionB.start();
        sessionA.wait_started();
        sessionB.wait_started();
        while(AmSession::getSessionNum()) { usleep(100); }
        sessionA.checkData();
        sessionB.checkData();
    } catch(const AmSession::Exception& except) {
        error = except.reason;
    } catch(const string& reason) {
        error = reason.c_str();
    }

    if(!error.empty()) FAIL() << "Exception - " << error.c_str() << std::endl;
}

TEST_F(FaxTest, DISABLED_DTLST38Test) {
    string error;
    try {
        unsigned int idx = AmConfig.sip_if_names[test_config::instance()->signalling_interface];
        string ip;
        if(AmConfig.sip_ifs[idx].proto_info.size()) ip = AmConfig.sip_ifs[idx].proto_info[0]->getIP();
        ASSERT_FALSE(ip.empty());
        ip.insert(0, "sip:");

        FaxSession sessionA(ip, OFFER), sessionB(ip, ANSWER);
        t38_option options;

        sessionA.setMediaTransport(TP_UDPTLSUDPTL);
        sessionA.setMediaType(MT_IMAGE);
        sessionA.getSdpOffer(sessionA.local);

        GTEST_ASSERT_EQ(sessionA.local.media.size(), 1);
        options.negotiateT38Options(sessionA.local.media[sessionA.RTPStream()->getSdpMediaIndex()].attributes);
        sessionA.t38->setOptions(options);

        sessionB.setMediaTransport(TP_UDPTLSUDPTL);
        sessionB.setMediaType(MT_IMAGE);
        GTEST_ASSERT_NE(sessionA.local.media.size(), 0);
        sessionB.getSdpAnswer(sessionA.local, sessionB.local);

        GTEST_ASSERT_EQ(sessionB.local.media.size(), 1);
        options.negotiateT38Options(sessionB.local.media[sessionA.RTPStream()->getSdpMediaIndex()].attributes);
        sessionB.t38->setOptions(options);

        sessionA.setRemoteSdp(sessionB.getLocalSdp());
        sessionB.setRemoteSdp(sessionA.getLocalSdp());
        EXPECT_EQ(sessionA.init(), 0);
        EXPECT_EQ(sessionB.init(), 0);
        sessionA.start();
        sessionB.start();
        sessionA.wait_started();
        sessionB.wait_started();
        while(AmSession::getSessionNum()) { usleep(100); }
        sessionA.checkData();
        sessionB.checkData();
    } catch(const AmSession::Exception& except) {
        error = except.reason;
    } catch(const string& reason) {
        error = reason.c_str();
    }

    if(!error.empty()) FAIL() << "Exception - " << error.c_str() << std::endl;
}

TEST_F(FaxTest, SingleT30Test) {
    string error;
    try {
        unsigned int idx = AmConfig.sip_if_names[test_config::instance()->signalling_interface];
        string ip;
        if(AmConfig.sip_ifs[idx].proto_info.size()) ip = AmConfig.sip_ifs[idx].proto_info[0]->getIP();
        ASSERT_FALSE(ip.empty());
        ip.insert(0, "sip:");

        FaxSession sessionA(ip, OFFER), sessionB(ip, ANSWER);
        t38_option options;

        sessionA.setMediaTransport(TP_RTPAVP);
        sessionB.setMediaType(MT_AUDIO);
        sessionA.getSdpOffer(sessionA.local);
        EXPECT_EQ(sessionA.local.media.size(), 1);

        sessionB.setMediaTransport(TP_RTPAVP);
        sessionB.setMediaType(MT_AUDIO);
        GTEST_ASSERT_NE(sessionA.local.media.size(), 0);
        sessionB.getSdpAnswer(sessionA.local, sessionB.local);
        GTEST_ASSERT_EQ(sessionB.local.media.size(), 1);

        sessionA.setRemoteSdp(sessionB.getLocalSdp());
        sessionB.setRemoteSdp(sessionA.getLocalSdp());
        GTEST_ASSERT_EQ(sessionA.init(), 0);
        GTEST_ASSERT_EQ(sessionB.init(), 0);
        sessionA.start();
        sessionB.start();
        sessionA.wait_started();
        sessionB.wait_started();
        while(AmSession::getSessionNum()) { usleep(100); }
        sessionA.checkData();
        sessionB.checkData();
    } catch(const AmSession::Exception& except) {
        error = except.reason;
    } catch(const string& reason) {
        error = reason.c_str();
    }

    if(!error.empty()) FAIL() << "Exception - " << error.c_str() << std::endl;
}

TEST_F(FaxTest, AudioToT38Test) {
    string error;
    try {
        unsigned int idx = AmConfig.sip_if_names[test_config::instance()->signalling_interface];
        string ip;
        if(AmConfig.sip_ifs[idx].proto_info.size()) ip = AmConfig.sip_ifs[idx].proto_info[0]->getIP();
        ASSERT_FALSE(ip.empty());
        ip.insert(0, "sip:");

        FaxSession sessionA(ip, OFFER), sessionB(ip, ANSWER);
        t38_option options;

        sessionA.setMediaTransport(TP_RTPAVP);
        sessionA.getSdpOffer(sessionA.local);
        GTEST_ASSERT_EQ(sessionA.local.media.size(), 1);

        sessionB.setMediaTransport(TP_RTPAVP);
        GTEST_ASSERT_NE(sessionA.local.media.size(), 0);
        sessionB.getSdpAnswer(sessionA.local, sessionB.local);
        GTEST_ASSERT_EQ(sessionB.local.media.size(), 1);

        sessionA.setRemoteSdp(sessionB.getLocalSdp());
        sessionB.setRemoteSdp(sessionA.getLocalSdp());
        GTEST_ASSERT_EQ(sessionA.init(), 0);
        GTEST_ASSERT_EQ(sessionB.init(), 0);

        sessionA.RTPStream()->setReuseMediaPort(false);
        sessionA.RTPStream()->addAdditionTransport();
        sessionA.setMediaTransport(TP_UDPTL);
        sessionA.setMediaType(MT_IMAGE);
        sessionA.setReuseMediaSlot(false);
        sessionA.getSdpOffer(sessionA.local);
        GTEST_ASSERT_EQ(sessionA.local.media.size(), 2);
        for(auto &media : sessionA.local.media) {
            if(media.type == MT_IMAGE)
                EXPECT_NE(media.port, 0);
            else
                EXPECT_EQ(media.port, 0);
        }

        sessionB.RTPStream()->setReuseMediaPort(false);
        sessionB.RTPStream()->addAdditionTransport();
        sessionB.setMediaTransport(TP_UDPTL);
        sessionB.setMediaType(MT_IMAGE);
        sessionB.getSdpAnswer(sessionA.local, sessionB.local);
        GTEST_ASSERT_EQ(sessionB.local.media.size(), 2);
        for(auto &media : sessionB.local.media) {
            if(media.type == MT_IMAGE)
                EXPECT_NE(media.port, 0);
            else
                EXPECT_EQ(media.port, 0);
        }

        sessionA.setRemoteSdp(sessionB.getLocalSdp());
        sessionB.setRemoteSdp(sessionA.getLocalSdp());
        EXPECT_EQ(sessionA.init(), 0);
        EXPECT_EQ(sessionB.init(), 0);

        sessionA.start();
        sessionB.start();
        sessionA.wait_started();
        sessionB.wait_started();
        while(AmSession::getSessionNum()) { usleep(100); }
        sessionA.checkData();
        sessionB.checkData();
    } catch(const AmSession::Exception& except) {
        error = except.reason;
    } catch(const string& reason) {
        error = reason.c_str();
    }

    if(!error.empty()) FAIL() << "Exception - " << error.c_str() << std::endl;
}

TEST_F(FaxTest, ReinviteT38Test) {
    string error;
    try {
        unsigned int idx = AmConfig.sip_if_names[test_config::instance()->signalling_interface];
        string ip;
        if(AmConfig.sip_ifs[idx].proto_info.size()) ip = AmConfig.sip_ifs[idx].proto_info[0]->getIP();
        ASSERT_FALSE(ip.empty());
        ip.insert(0, "sip:");

        FaxSession sessionA(ip, OFFER), sessionB(ip, ANSWER);
        t38_option options;

        sessionA.RTPStream()->setReuseMediaPort(false);
        sessionA.setMediaTransport(TP_RTPAVP);
        sessionA.getSdpOffer(sessionA.local);
        GTEST_ASSERT_EQ(sessionA.local.media.size(), 1);

        sessionB.RTPStream()->setReuseMediaPort(false);
        sessionB.setMediaTransport(TP_RTPAVP);
        GTEST_ASSERT_NE(sessionA.local.media.size(), 0);
        sessionB.getSdpAnswer(sessionA.local, sessionB.local);
        GTEST_ASSERT_EQ(sessionB.local.media.size(), 1);

        sessionA.setRemoteSdp(sessionB.getLocalSdp());
        sessionB.setRemoteSdp(sessionA.getLocalSdp());
        GTEST_ASSERT_EQ(sessionA.init(), 0);
        GTEST_ASSERT_EQ(sessionB.init(), 0);

        sessionB.RTPStream()->setReuseMediaPort(true);
        sessionB.setMediaType(MT_IMAGE);
        sessionB.setReuseMediaSlot(true);
        sessionB.setMediaTransport(TP_UDPTL);
        sessionB.RTPStream()->addAdditionTransport();
        sessionB.getSdpOffer(sessionB.local);
        GTEST_ASSERT_EQ(sessionB.local.media.size(), 1);

        sessionB.RTPStream()->setReuseMediaPort(false);
        sessionA.setMediaTransport(TP_UDPTL);
        sessionA.RTPStream()->addAdditionTransport();
        sessionA.setMediaType(MT_IMAGE);
        sessionA.getSdpAnswer(sessionB.local, sessionA.local);
        GTEST_ASSERT_EQ(sessionA.local.media.size(), 1);

        sessionA.setRemoteSdp(sessionB.getLocalSdp());
        sessionB.setRemoteSdp(sessionA.getLocalSdp());
        GTEST_ASSERT_EQ(sessionA.init(), 0);
        GTEST_ASSERT_EQ(sessionB.init(), 0);

        sessionA.start();
        sessionB.start();
        sessionA.wait_started();
        sessionB.wait_started();
        while(AmSession::getSessionNum()) { usleep(100); }
        sessionA.checkData();
        sessionB.checkData();
    } catch(const AmSession::Exception& except) {
        error = except.reason;
    } catch(const string& reason) {
        error = reason.c_str();
    }

    if(!error.empty()) FAIL() << "Exception - " << error.c_str() << std::endl;
}

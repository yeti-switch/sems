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

using std::string;

#define OFFER  1
#define ANSWER 2

class TestSession;

class TestAudio : public AmNullAudio
{
    TestSession* session_;
public:
    TestAudio(TestSession* session)
    : AmNullAudio(test_config::instance()->stress_session_duration, test_config::instance()->stress_session_duration)
    , session_(session), put_count_data(0), get_count_data(0){}
    ~TestAudio(){}
    int get(unsigned long long system_ts, unsigned char * buffer, int output_sample_rate, unsigned int nb_samples) override;
    int put(unsigned long long system_ts, unsigned char * buffer, int input_sample_rate, unsigned int size) override;

    int put_count_data;
    int get_count_data;
};

class TestSession : public AmSession
{
    AmSdp local;
    AmSdp* remote;
    TestAudio audio;
    TestPayloadProvider pl_prov;
    int OAtype;
    AmCondition<bool> started;
public:
    TestSession(const string& remote_uri, int OA)
    : OAtype(OA), remote(0), audio(this)
    , started(false)
    {
        RTPStream()->setMonitorRTPTimeout(false);

        dlg->setRemoteUri(remote_uri);
        RTPStream()->setPayloadProvider(&pl_prov);
        if(OAtype == OFFER) {
            getSdpOffer(local);
            EXPECT_EQ(local.media.size(), 1);
        }
        setLocalTag();
    }
    ~TestSession()
    {
    }

    void setRemoteSdp(AmSdp* remoteSdp)
    {
        remote = remoteSdp;
        if(OAtype == ANSWER) {
            GTEST_ASSERT_NE(remoteSdp->media.size(), 0);
            getSdpAnswer(*remoteSdp, local);
        }
    }

    AmSdp* getLocalSdp()
    {
        return &local;
    }

    int init()
    {
        setInOut(&audio, &audio);
        if(AmSessionContainer::instance()->addSession(getLocalTag(), this) != AmSessionContainer::Inserted) return EXIT_FAILURE;
        return RTPStream()->init(local, *remote);
    }

    virtual void onStart() override
    {
        started.set(true);
        RTPStream()->resumeReceiving();
        startMediaProcessing();
    }
    
    void checkData() {
        EXPECT_EQ(audio.put_count_data, audio.get_count_data);
    }
    
    void wait_started() {
        started.wait_for();
    }
};

int TestAudio::get(unsigned long long system_ts, unsigned char * buffer, int output_sample_rate, unsigned int nb_samples)
{
    int ret = AmNullAudio::get(system_ts, buffer, output_sample_rate, nb_samples);
    if(ret < 0) {
        AmMediaProcessor::instance()->clearSession(session_);
        return -1;
    }
    get_count_data += ret;
    return ret;
}

int TestAudio::put(unsigned long long system_ts, unsigned char * buffer, int input_sample_rate, unsigned int size)
{
    int ret = AmNullAudio::put(system_ts, buffer, input_sample_rate, size);
    put_count_data += ret;
    return ret;
}

class RTPStream : public ::testing::Test
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

TEST_F(RTPStream, SingleStreams) {
    string error;
    try {
        unsigned int idx = AmConfig.sip_if_names[test_config::instance()->signalling_interface];
        string ip;
        if(AmConfig.sip_ifs[idx].proto_info.size()) ip = AmConfig.sip_ifs[idx].proto_info[0]->getIP();
        ASSERT_FALSE(ip.empty());
        ip.insert(0, "sip:");
        TestSession sessionA(ip, OFFER), sessionB(ip, ANSWER);
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


TEST_F(RTPStream, DISABLED_StressTest)
{
    string error;
    try {
        TestSession *session;
        session = (TestSession*)malloc(sizeof(TestSession)*2*test_config::instance()->stress_session_pairs_count);
        
        unsigned int idx = AmConfig.sip_if_names[test_config::instance()->signalling_interface];
        string ip;
        if(AmConfig.sip_ifs[idx].proto_info.size()) ip = AmConfig.sip_ifs[idx].proto_info[0]->getIP();
        ASSERT_FALSE(ip.empty());
        ip.insert(0, "sip:");
        
        for(int i = 0; i < test_config::instance()->stress_session_pairs_count; i++) {
            TestSession* sessionA  = new (&session[i*2]) TestSession(ip, OFFER);
            TestSession* sessionB = new (&session[1 + i*2]) TestSession(ip, ANSWER);
            sessionA->setRemoteSdp(sessionB->getLocalSdp());
            sessionB->setRemoteSdp(sessionA->getLocalSdp());
            EXPECT_EQ(sessionA->init(), 0);
            EXPECT_EQ(sessionB->init(), 0);
            sessionA->start();
            sessionB->start();
            sessionA->wait_started();
            sessionB->wait_started();
        }
        while(AmSession::getSessionNum()) { usleep(100); }
        for(int i = 0; i < test_config::instance()->stress_session_pairs_count; i++) {
            session[i*2].checkData();
            session[i*2 + 1].checkData();
        }
        free(session);
    } catch(const AmSession::Exception& except) {
        error = except.reason;
    } catch(const string& reason) {
        error = reason.c_str();
    }
    
    if(!error.empty()) FAIL() << "Exception - " << error.c_str() << std::endl;
}

#include <gtest/gtest.h>
#include <AmRtpReceiver.h>
#include "../WorkersManager.h"
#include <AmLcConfig.h>

class FakeRtpSession : public AmRtpSession
{
public:
    FakeRtpSession(){}
    ~FakeRtpSession(){}

    void recvPacket(int fd) override{}
};

class ReceiverTask : public ITask
{
    FakeRtpSession rtp_s;
    int ctx_id;
    int sd;
public:
    ReceiverTask() : ctx_id(-1), sd(eventfd(rand(), EFD_NONBLOCK)){}
    ~ReceiverTask(){ close(sd); }

    int execute() override
    {
        ctx_id = AmRtpReceiver::instance()->addStream(sd, &rtp_s, ctx_id);
        if(ctx_id < 0) {
            CLASS_DBG("error on add/resuming stream. ctx_id = %d", ctx_id);
            return EXIT_FAILURE;
        }
        usleep(1000);
        AmRtpReceiver::instance()->removeStream(sd, ctx_id);
        return EXIT_SUCCESS;
    }
};

TEST(Receiver, AddRemoveStream)
{
    AmRtpReceiver::instance()->start();
    usleep(10000);
    ReceiverTask* ftask = new ReceiverTask[worker_manager::instance()->get_workers()];
    for(int i = 0; i < worker_manager::instance()->get_workers(); i++) {
        EXPECT_EQ(worker_manager::instance()->run_task(&ftask[i]), true);
    }

    for(int i = 0; i < worker_manager::instance()->get_workers(); i++) {
        ftask[i].join(2000);
        EXPECT_EQ(ftask[i].ret_, EXIT_SUCCESS);
    }
    delete[] ftask;
    AmRtpReceiver::instance()->dispose();
}

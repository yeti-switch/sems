#include <gtest/gtest.h>
#include <string>
#include <AmAppTimer.h>
#include <DirectAppTimer.h>
#include <AmEventProcessingThread.h>
#include <AmEventDispatcher.h>

#define TIMER_RECEIVER_QUEUE_NAME "TimerReceiver"

class TimerEvent : public AmEvent
{
public:
    int seq;
    TimerEvent(int seq) : AmEvent(0), seq(seq){}
    AmEvent * clone() override {
        return new TimerEvent(*this);
    }
};

class TimerTest;

class ReuseTimer : public DirectAppTimer
{
public:
    int seq;
    TimerTest* test;

    ReuseTimer(TimerTest* t) : seq(0), test(t){}

    void onTimer() override;
};

class TimerTest : public AmEventProcessingThread, public ::testing::Test
{
protected:
    friend class ReuseTimer;
    ReuseTimer timer;
    bool is_stop;
    int seq;
public:
    TimerTest() : timer(this), is_stop(false), seq(0){}
    ~TimerTest() {
    }

    void SetUp() override {
        AmAppTimer::instance()->start();
        AmEventDispatcher::instance()->addEventQueue(TIMER_RECEIVER_QUEUE_NAME, this);
    }
    void TearDown() override {
        AmEventDispatcher::instance()->delEventQueue(TIMER_RECEIVER_QUEUE_NAME);
        AmAppTimer::instance()->stop(true);
    }

    void run() override
    {
        while (!is_stop) {
            waitForEvent();
            processEvents();
        }
    }

    void onEvent(AmEvent* event) override {
        TimerEvent* tev = dynamic_cast<TimerEvent*>(event);
        if(tev) {
            EXPECT_EQ(tev->seq, seq);
            if(tev->seq == 0) {
                seq++;

                //new logic: object is new(other content)
                //timer shouldn't removed
                /*timer.seq++;
                AmAppTimer::instance()->removeTimer(timer);*/
            } else if(tev->seq == 1) {
                is_stop = true;
            }
        }
    }
};

void ReuseTimer::onTimer()
{
    AmEventDispatcher::instance()->post(TIMER_RECEIVER_QUEUE_NAME, new TimerEvent(seq));
    test->timer.seq++;
    test->timer.set(0);
}

TEST_F(TimerTest, ReuseTimer) {
    timer.set(0);
    run();
}




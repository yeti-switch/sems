#pragma once

#include <AmEvent.h>
#include <AmEventFdQueue.h>

#include <gtest/gtest.h>

#define TEST_CLIENT_QUEUE "test_client_queue"

/* TestUserData */

class TestUserData : public AmObject {
  public:
    string value;
    TestUserData()
        : value("")
    {
    }
};

/* TestClient */

class TestClient : public AmThread, public AmEventFdQueue, public AmEventHandler {
  private:
    int               epoll_fd;
    AmCondition<bool> stopped;
    AmEventFd         stop_event;
    string            queue_name;

  protected:
    void run() override;
    void on_stop() override;
    void process(AmEvent *e) override;

  public:
    TestClient();
    TestClient(const string &queue_name);
    TestClient(const TestClient &) = delete;
    virtual ~TestClient();
    virtual void reset();

    AmCondition<bool> reply_available;
    AmArg             reply_data;
    AmObject         *reply_user_data;
};

inline void wait_for_cond(AmCondition<bool> &cond)
{
    if (cond.get() == false)
        cond.wait_for();

    GTEST_ASSERT_EQ(cond.get(), true);
    cond.set(false);
}

inline void stop(TestClient &client)
{
    client.stop(true);
    client.reset();
}

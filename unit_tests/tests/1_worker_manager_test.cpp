#include <gtest/gtest.h>
#include "../WorkersManager.h"

#define TEST_VALUE  10

class EmptyTask : public ITask
{
public:
    EmptyTask() : value(0) {}
    ~EmptyTask(){}

    int execute() override
    {
        value = TEST_VALUE;
        return 0;
    }

    int value;
};

class FreezeTask : public ITask
{
public:
    FreezeTask() : value(0), cond_(false) {}
    ~FreezeTask(){}

    int execute() override
    {
        cond_.wait_for();
        value = TEST_VALUE;
        return 0;
    }

    void stop() override
    {
        cond_.set(true);
    }

    int value;
    AmCondition<bool> cond_;
};

TEST(WorkerManager, RunEmptyTask)
{
    EmptyTask task;
    EXPECT_EQ(worker_manager::instance()->run_task(&task), true);
    task.join(1000);
    EXPECT_EQ(task.value, TEST_VALUE);
}

TEST(WorkerManager, RunFreezeTask)
{
    FreezeTask task;
    EXPECT_EQ(worker_manager::instance()->run_task(&task), true);
    task.join(1000);
    EXPECT_EQ(task.value, 0);
    task.stop();
    task.join(1000);
    EXPECT_EQ(task.value, TEST_VALUE);
}

TEST(WorkerManager, RunMuchTask)
{
    FreezeTask* ftask = new FreezeTask[worker_manager::instance()->get_workers()];
    for(int i = 0; i < worker_manager::instance()->get_workers(); i++) {
        EXPECT_EQ(worker_manager::instance()->run_task(&ftask[i]), true);
    }

    EmptyTask etask;
    EXPECT_EQ(worker_manager::instance()->run_task(&etask), false);

    for(int i = 0; i < worker_manager::instance()->get_workers(); i++) {
        ftask[i].stop();
        ftask[i].join(1000);
        EXPECT_EQ(ftask[i].value, TEST_VALUE);
    }
    delete[] ftask;
}

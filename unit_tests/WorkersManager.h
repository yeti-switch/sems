#ifndef WORKER_CONTAINER_H
#define WORKER_CONTAINER_H

#include <singleton.h>
#include <atomic>
#include <vector>
#include <ev.h>

using std::vector;

#define JOIN_NO_TIMEOUT -1
#define DEFAULT_WORKERS_COUNT   10

class ITask
{
public:
    struct TStatus
    {
        enum TaskStatus
        {
            InQueue,
            Running,
            Finished
        };
        TStatus(TaskStatus status_):status(status_){}
        TaskStatus status;
        operator bool() const {
            return Finished == status;
        }
    };

    ITask() : status_(TStatus::InQueue), ret_(-1){}
    virtual ~ITask(){}

    virtual int execute() = 0;
    virtual void stop(){}
    virtual void join(int ms = JOIN_NO_TIMEOUT)
    {
        if(ms == JOIN_NO_TIMEOUT) {
            status_.wait_for();
        } else {
            status_.wait_for_to(ms);
        }
    }

    AmCondition<TStatus> status_;
    int ret_;
};

class WorkerContainer
{
    class Worker : public AmThread
    {
    public:
        Worker();
        virtual ~Worker();

        void on_stop() override;
        void run() override;

        bool run_task(ITask* task);
    protected:
        void execute_task();
    private:
        struct ev_loop             *loop;
        struct ev_async            async_stop;
        struct ev_async            async_task;
        std::atomic<ITask*>        running_task;
    };

    vector<Worker*> workers;
protected:
    WorkerContainer();
    ~WorkerContainer();
public:
    void init(unsigned int workers = DEFAULT_WORKERS_COUNT);
    bool run_task(ITask* task);
    int get_workers();
    void dispose();
};

typedef singleton<WorkerContainer> worker_manager;

#endif/*WORKER_CONTAINER_H*/

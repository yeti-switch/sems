#include "WorkersManager.h"

template <typename T1, typename T2> struct offset_of_impl {
    static T2               object;
    static constexpr size_t offset(T1 T2::*member)
    {
        return size_t(&(offset_of_impl<T1, T2>::object.*member)) - size_t(&offset_of_impl<T1, T2>::object);
    }
};

template <typename T1, typename T2> T2                      offset_of_impl<T1, T2>::object;
template <typename T1, typename T2> inline constexpr size_t offset_of(T1 T2::*member)
{
    return offset_of_impl<T1, T2>::offset(member);
}

WorkerContainer::Worker::Worker()
    : running_task(0)
{
    loop = ev_loop_new();
    if (!loop) {
        INFO("couldn't create an event_loop");
        exit(1);
    }

    ev_async_init(&async_task, [](EV_P_ ev_async *async_task, int) {
        auto worker = reinterpret_cast<Worker *>(((char *)async_task) - offset_of(&Worker::async_task));
        worker->execute_task();
    });
    ev_async_start(loop, &async_task);
}

WorkerContainer::Worker::~Worker()
{
    ev_async_stop(loop, &async_stop);
    ev_async_stop(loop, &async_task);
    ev_loop_destroy(loop);
}

void WorkerContainer::Worker::run()
{
    setThreadName("worker");
    ev_run(loop);
}

void WorkerContainer::Worker::on_stop()
{
    ev_async_init(&async_stop, [](EV_P_ ev_async *, int) { ev_break(loop); });
    ev_async_start(loop, &async_stop);
    ev_async_send(loop, &async_stop);
}

bool WorkerContainer::Worker::run_task(ITask *task)
{
    {
        ITask *_t = 0;
        if (!running_task.compare_exchange_strong(_t, task))
            return false;
    }
    ev_async_send(loop, &async_task);
    return true;
}

void WorkerContainer::Worker::execute_task()
{
    ITask *task = running_task.load();
    if (task) {
        task->status_.set(ITask::TStatus::Running);
        task->ret_ = task->execute();
        task->status_.set(ITask::TStatus::Finished);
    }
    running_task.store(0);
}

WorkerContainer::WorkerContainer() {}

WorkerContainer::~WorkerContainer() {}

void WorkerContainer::init(unsigned int workers_)
{
    for (unsigned int i = 0; i < workers_; i++) {
        workers.push_back(new Worker);
        workers.back()->start();
    }
}

bool WorkerContainer::run_task(ITask *task)
{
    for (auto &worker : workers) {
        if (worker->run_task(task))
            return true;
    }

    return false;
}

int WorkerContainer::get_workers()
{
    return workers.size();
}

void WorkerContainer::dispose()
{
    for (auto &worker : workers) {
        worker->stop(true);
        delete worker;
    }

    workers.clear();
}

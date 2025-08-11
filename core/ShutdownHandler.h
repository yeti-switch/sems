#pragma once

#include <string>
#include <cstdint>

class ShutdownHandlersProcessor;

class ShutdownHandler {
    // descriptive name for RPC output
    std::string name;
    // queue name for GracefulShutdownRequested, GracefulShutdownCancelled events
    std::string queue_name;

    // flag which is managed by ShutdownHandlersProcessor
    // terminate application if all handlers are finished
    bool finished;

    // flag is used by module thread to switch between operational and shutdown modes
    bool shutdown_mode;
    // active tasks count for RPC
    uint64_t tasks_count;

    ShutdownHandlersProcessor &processor;

    // must be implemented by module and return active tasks count
    // module considered finished if the tasks count is 0
    virtual uint64_t get_active_tasks_count() = 0;

  public:
    ShutdownHandler(const std::string &name, const std::string &queue_name);

    void onShutdownRequested();
    void onShutdownCancelled();

    // set/clear must be called from ShutdownHandlersProcessor only
    // guarded by ShutdownHandlersProcessor::mutex
    void setFinished() { finished = true; }
    void clearFinished() { finished = false; }

    // must be called at places where the active tasks count could be decreased
    void checkFinished();

    const std::string &getName() { return name; }
    const std::string &getQueueName() { return queue_name; }
    bool               isFinished() { return finished; }
    bool               isShutdownMode() { return shutdown_mode; }
    uint64_t           getActiveTasksCount() { return tasks_count; }
};

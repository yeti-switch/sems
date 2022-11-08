#include "ShutdownHandler.h"

#include "ShutdownHandlersProcessor.h"
#include "AmLcConfig.h"

ShutdownHandler::ShutdownHandler(const std::string &name,
                                 const std::string &queue_name)
  : name(name),
    queue_name(queue_name),
    finished(false),
    shutdown_mode(false),
    processor(AmConfig.shutdown_handlers_processor)
{
    processor.registerShutdownHandler(this);
}

void ShutdownHandler::checkFinished()
{
    if(!shutdown_mode)
        return;

    tasks_count = get_active_tasks_count();
    if(0==tasks_count)
        processor.onHandlerFinished(this);
}

void ShutdownHandler::onShutdownRequested()
{
    shutdown_mode = true;

    checkFinished();
}

void ShutdownHandler::onShutdownCancelled()
{
    shutdown_mode = false;
}

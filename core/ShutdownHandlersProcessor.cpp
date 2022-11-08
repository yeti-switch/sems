#include "ShutdownHandlersProcessor.h"

#include "AmLcConfig.h"
#include "AmSessionContainer.h"
#include "AmEvent.h"

#include <signal.h>

void ShutdownHandlersProcessor::shutdownIfFinished()
{
    for(auto h: handlers) {
        if(!h->isFinished()) {
            //found handler with active tasks
            return;
        }
    }

    INFO("no active shutdown handlers in graceful shutdown mode. shutdown");
    kill(getpid(),SIGINT);
}

void ShutdownHandlersProcessor::registerShutdownHandler(ShutdownHandler *handler)
{
    AmLock l(mutex);
    handlers.emplace_back(handler);
}

void ShutdownHandlersProcessor::onHandlerFinished(ShutdownHandler *handler)
{
    if(!AmConfig.shutdown_mode)
        return;

    AmLock l(mutex);

    handler->setFinished();

    shutdownIfFinished();
}

void ShutdownHandlersProcessor::onShutdownRequested()
{
    AmLock l(mutex);

    for(auto h: handlers)
        h->clearFinished();

    for(auto h: handlers) {
        if(!AmSessionContainer::instance()->postEvent(
            h->getQueueName(),
            new AmSystemEvent(AmSystemEvent::GracefulShutdownRequested)))
        {
            //failed to post event to the graceful shutdown handler queue
            //consider it finished
            h->setFinished();
        }
    }

    shutdownIfFinished();
}

void ShutdownHandlersProcessor::onShutdownCancelled()
{
    for(auto h: handlers) {
        h->clearFinished();
        AmSessionContainer::instance()->postEvent(
            h->getQueueName(),
            new AmSystemEvent(AmSystemEvent::GracefulShutdownCancelled));
    }
}

void ShutdownHandlersProcessor::getStatus(AmArg &status)
{
    status.assertArray();
    for(auto h : handlers) {
        status.push(AmArg());
        AmArg &a = status.back();
        a["name"] = h->getName();
        a["queue_name"] = h->getQueueName();
        a["finished"] = h->isFinished();
        a["shutdown_mode"] = h->isShutdownMode();
        a["tasks_count"] = h->isShutdownMode() ? h->getActiveTasksCount() : AmArg();
    }
}

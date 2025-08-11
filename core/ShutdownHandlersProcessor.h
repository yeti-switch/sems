#pragma once

#include "AmThread.h"
#include "ShutdownHandler.h"
#include "AmArg.h"

#include <vector>

class ShutdownHandlersProcessor {
    std::vector<ShutdownHandler *> handlers;
    AmMutex                        mutex;

    void shutdownIfFinished();

  public:
    void registerShutdownHandler(ShutdownHandler *handler);
    void onHandlerFinished(ShutdownHandler *handler);

    bool empty() { return handlers.empty(); }

    void onShutdownRequested();
    void onShutdownCancelled();

    void getStatus(AmArg &status);
};

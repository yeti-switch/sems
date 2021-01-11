#pragma once

#include "AmEvent.h"

#define OPTIONS_PROBER_QUEUE "options_prober"

struct OptionsProberCtlEvent
  : public AmEvent
{
    enum Action {
        Flush = 0,
        Add,
        Remove
    } action;
    AmArg probers_list;

    OptionsProberCtlEvent(Action action)
      : AmEvent(0),
        action(action)
    { }

    OptionsProberCtlEvent(Action action, const AmArg &probers_list)
      : AmEvent(0),
        action(action),
        probers_list(probers_list)
    { }

    virtual ~OptionsProberCtlEvent() {}
};

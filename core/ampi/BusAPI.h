#pragma once

#include "eventfd.h"
#include "timerfd.h"
#include "AmApi.h"
#include "AmSession.h"
#include "AmEventFdQueue.h"
#include <singleton.h>

#include <string>
#include <map>
#include <deque>
#include <vector>

using std::map;
using std::string;

#define BUS_EVENT_QUEUE "event_bus"

struct BusMsg
  : public AmEvent
{
    typedef enum {
        New = 0,
        Pending,
    } msg_state_t;

    msg_state_t     state;
    int             status;
    bool            is_query;
    string          local_tag;
    string          application_method;
    string          body;
    uint64_t        updated;

    BusMsg(bool _is_query,string _local_tag, string _application_method, string _body, int _status = 0)
      : AmEvent(0),
        state(New),
        status(_status),
        is_query(_is_query),
        local_tag(_local_tag),
        application_method(_application_method),
        body(_body)
    {}

    ~BusMsg() {}
};

struct BusReplyEvent
  : public AmEvent
{
    enum BusResult {
        Success,
        Error
    } result;

    map<string, string> params;
    AmArg data;

    BusReplyEvent(BusResult  result, map<string, string> &_params)
    : AmEvent(0),
      result(result)
    {
        std::copy(_params.begin(), _params.end(), std::inserter(params, params.end()) );
    }

    BusReplyEvent(BusResult  result, const AmArg &data)
    : AmEvent(0),
      result(result),
      data(data)
    { }

    BusReplyEvent(BusResult  result, map<string, string> &_params, const AmArg &data)
    : AmEvent(0),
      result(result),
      data(data)
    {
        std::copy(_params.begin(), _params.end(), std::inserter(params, params.end()) );
    }

    BusReplyEvent()
    : AmEvent(0),
      result(Success)
    {}

};

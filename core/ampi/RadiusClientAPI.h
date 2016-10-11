#pragma once

#include "AmEvent.h"
#include "sys/time.h"

#define RADIUS_EVENT_QUEUE "radius_client"

#define RADIUS_RESPONSE_TIMEOUT     2001
#define RADIUS_REQUEST_ERROR        2002
#define RADIUS_INVALID_SERVER_ID    2003
#define RADIUS_INVALID_RESPONSE     2004
#define RADIUS_RESPONSE_REJECT      2005
#define RADIUS_UNSUPPORTED          2006

struct RadiusAccountingRules {
    bool enable_start_accounting,
         enable_interim_accounting,
         enable_stop_accounting;
    int interim_accounting_interval;

    RadiusAccountingRules()
    : enable_start_accounting(false),
      enable_interim_accounting(false),
      enable_stop_accounting(false),
      interim_accounting_interval(0)
    {}

    RadiusAccountingRules(
        bool start,
        bool interim,
        bool stop,
        int interval)
    : enable_start_accounting(start),
      enable_interim_accounting(interim),
      enable_stop_accounting(stop),
      interim_accounting_interval(interval)
    {}

    void pack(AmArg &arg) const
    {
        arg.push(enable_start_accounting);
        arg.push(enable_interim_accounting);
        arg.push(enable_stop_accounting);
        arg.push(interim_accounting_interval);
    }

    void unpack(const AmArg& arg)
    {
        if(!isArgArray(arg)) return;
        enable_start_accounting = arg.get(0).asBool();
        enable_interim_accounting = arg.get(1).asBool();
        enable_stop_accounting = arg.get(2).asBool();
        interim_accounting_interval = arg.get(3).asInt();
    }
};

struct RadiusRequestEvent
  : public AmEvent
{
  string session_id;
  unsigned int server_id;
  struct timeval created_at;
  std::map<string,string> values_hash;

  enum RadiusRequestType {
    Auth = 0,
    Accounting
  };

  enum RadiusAccountingType {
    Start = 0,
    Interim,
    End
  } accounting_type;

  RadiusRequestEvent(
    unsigned int server_id,
    string session_id,
    std::map<string,string> values)
    : AmEvent(Auth),
      server_id(server_id),
      session_id(session_id),
      values_hash(values)
  {
      gettimeofday(&created_at,NULL);
  }

  RadiusRequestEvent(
    RadiusAccountingType type,
    unsigned int server_id,
    string session_id,
    std::map<string,string> values)
    : AmEvent(Accounting),
      accounting_type(type),
      server_id(server_id),
      session_id(session_id),
     values_hash(values)
  {
      gettimeofday(&created_at,NULL);
  }
};

struct RadiusReplyEvent
  : public AmEvent
{
  enum RadiusResult {
    Accepted,
    Rejected,
    Error
  } result;

  int error_code;
  bool reject_on_error;

  RadiusReplyEvent(RadiusResult result, int error_code, bool reject_on_error)
    : AmEvent(0),
      result(result),
      error_code(error_code),
      reject_on_error(reject_on_error)
  {}
};


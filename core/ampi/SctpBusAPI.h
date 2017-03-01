#pragma once

#include "AmEvent.h"
#include "sys/time.h"

#define SCTP_BUS_EVENT_QUEUE "sctp_bus"

struct SctpBusSendEvent
  : public AmEvent
{
  string src_session_id;
  string dst_session_id;
  //struct timeval created_at;
  AmArg data;

  SctpBusSendEvent(
    const string &src_session_id,
    const string &dst_session_id,
    const AmArg &data)
    : AmEvent(0),
      src_session_id(src_session_id),
      dst_session_id(dst_session_id),
      data(data)
  {
    //gettimeofday(&created_at,NULL);
  }
};

struct SctpBusEvent
  : public AmEvent
{
  int sender_node_id;
  string sender_session_id;
  AmArg data;

  SctpBusEvent(
    int sender_node_id,
    const string &sender_session_id,
    const AmArg &data = AmArg())
    : AmEvent(0),
      sender_node_id(sender_node_id),
      sender_session_id(sender_session_id),
      data(data)
  {}
};


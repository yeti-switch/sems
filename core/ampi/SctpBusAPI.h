#pragma once

#include "AmEvent.h"
#include "sys/time.h"

#define SCTP_BUS_EVENT_QUEUE "sctp_bus"

#include <sys/socket.h>

struct SctpBusAddConnection
  : public AmEvent
{
  unsigned int connection_id;
  sockaddr_storage remote_address;
  int reconnect_interval;
  string event_sink;
  SctpBusAddConnection(): AmEvent(0) {}
};

struct SctpBusRemoveConnection
  : public AmEvent
{
  unsigned int connection_id;
  SctpBusRemoveConnection(): AmEvent(0) {}
};

struct SctpBusConnectionStatus
  : public AmEvent
{
  unsigned int id;
  enum status_t {
    Connected,
    Closed,
    Removed
  } status;

  SctpBusConnectionStatus(unsigned int id, status_t status)
    : AmEvent(0),
      id(id),
      status(status)
  {}
};

struct SctpBusSendEvent
  : public AmEvent
{
  string src_session_id;
  string dst_session_id;
  AmArg data;

  SctpBusSendEvent(
    const string &src_session_id,
    const string &dst_session_id,
    const AmArg &data)
    : AmEvent(0),
      src_session_id(src_session_id),
      dst_session_id(dst_session_id),
      data(data)
  { }
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

struct SctpBusRawRequest
  : public AmEvent
{
  int src_id;
  string src_session_id;
  int dst_id;
  string dst_session_id;

  uint64_t cseq;
  int reply_timeout;

  string data;

  SctpBusRawRequest(
    const string &src_session_id,
    int dst_connection_id,
    const string &dst_session_id,
    int reply_timeout = 0)
    : AmEvent(0),
      src_session_id(src_session_id),
      dst_id(dst_connection_id),
      dst_session_id(dst_session_id),
      reply_timeout(reply_timeout)
  { }

  SctpBusRawRequest(
    const string &src_session_id,
    int dst_connection_id,
    const string &dst_session_id,
    const string &data,
    int reply_timeout = 0)
    : AmEvent(0),
      src_session_id(src_session_id),
      dst_id(dst_connection_id),
      dst_session_id(dst_session_id),
      reply_timeout(reply_timeout),
      data(data)
  { }
};

struct SctpBusRawReply
  : public AmEvent
{
    SctpBusRawRequest req;

    enum result_code {
        RES_OK = 0,
        RES_TIMEOUT,
        RES_NOT_CONNECTED,
        RES_SEND_SOCKET_ERROR
    } result;

    string data;

    SctpBusRawReply(
      const SctpBusRawRequest &req)
      : AmEvent(0),
        req(req),
        result(RES_OK)
    { }

    SctpBusRawReply(
      const SctpBusRawRequest &req,
      const string &data)
      : AmEvent(0),
        req(req),
        result(RES_OK),
        data(data)
    { }

    SctpBusRawReply(
      const SctpBusRawRequest &req,
      result_code result)
      : AmEvent(0),
        req(req),
        result(result)
    { }
};


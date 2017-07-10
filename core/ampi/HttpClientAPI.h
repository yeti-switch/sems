#pragma once

#include "AmEvent.h"
#include "sys/time.h"

#define HTTP_EVENT_QUEUE "http"

struct HttpEvent {
  enum Type {
      Upload = 0,
      Post
  };

  string session_id;
  string token;
  struct timeval created_at;
  unsigned int failover_idx;
  unsigned int attempt;

  HttpEvent(
      string session_id, string token,
      unsigned int failover_idx = 0,
      unsigned int attempt = 0)
    : session_id(session_id), token(token),
      failover_idx(failover_idx),
      attempt(attempt)
  {
      gettimeofday(&created_at,NULL);
  }
};


struct HttpUploadEvent
  : public HttpEvent, AmEvent
{

  string file_path;
  string file_name;
  string destination_name;

  HttpUploadEvent(string destination_name, string file_name, string file_path, string token, string session_id = string())
    : AmEvent(Upload),
      HttpEvent(session_id,token,failover_idx),
      destination_name(destination_name),
      file_name(file_name),
      file_path(file_path)
  { }

  HttpUploadEvent(const HttpUploadEvent &src)
    : AmEvent(Upload),
      HttpEvent(src.session_id,src.token,src.failover_idx,src.attempt),
      destination_name(src.destination_name),
      file_name(src.file_name),
      file_path(src.file_path)
  {}
};

struct HttpUploadResponseEvent
  : public AmEvent
{

  long int code;
  string token;

  HttpUploadResponseEvent(long int code, string token = string())
    : AmEvent(E_PLUGIN),
      code(code),
      token(token)
  {}
};

struct HttpPostEvent
  : public HttpEvent, AmEvent
{
  string data;
  string destination_name;

  HttpPostEvent(string destination_name, string data, string token, string session_id = string())
    : AmEvent(Post),
      HttpEvent(session_id,token),
      destination_name(destination_name),
      data(data)
  {}

  HttpPostEvent(const HttpPostEvent &src)
    : AmEvent(Post),
      HttpEvent(src.session_id,src.token,src.failover_idx,src.attempt),
      destination_name(src.destination_name),
      data(src.data)
  {}
};

struct HttpPostResponseEvent
  : public AmEvent
{

  long int code;
  string token;
  string data;

  HttpPostResponseEvent(long int code, string &data, string token = string())
    : AmEvent(E_PLUGIN),
      code(code),
      data(data),
      token(token)
  {}
};

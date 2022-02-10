#pragma once

#include "AmEvent.h"
#include "sys/time.h"

#define HTTP_EVENT_QUEUE "http"

struct HttpEvent
  : public AmEvent
{
  enum Type {
      Upload = 0,
      Post,
      MultiPartForm,
      Get,
      TriggerSyncContext
  };

  string session_id;
  string token;
  string sync_ctx_id;
  struct timeval created_at;
  unsigned int failover_idx;
  unsigned int attempt;

  HttpEvent(
      int event_id,
      string session_id, string token, const string &sync_ctx_id = string(),
      unsigned int failover_idx = 0,
      unsigned int attempt = 0)
    : AmEvent(event_id),
      session_id(session_id), token(token), sync_ctx_id(sync_ctx_id),
      failover_idx(failover_idx),
      attempt(attempt)
  {
      gettimeofday(&created_at,NULL);
  }
  virtual ~HttpEvent(){}
};


struct HttpUploadEvent
  : public HttpEvent
{

  string file_path;
  string file_name;
  string destination_name;

  HttpUploadEvent(string destination_name, string file_name, string file_path, string token,
                  string session_id = string(),
                  const string &sync_ctx_id = string())
    : HttpEvent(Upload, session_id,token,sync_ctx_id),
      destination_name(destination_name),
      file_name(file_name),
      file_path(file_path)
  { }

  HttpUploadEvent(const HttpUploadEvent &src)
    : HttpEvent(Upload, src.session_id,src.token,src.sync_ctx_id,src.failover_idx,src.attempt),
      destination_name(src.destination_name),
      file_name(src.file_name),
      file_path(src.file_path)
  {}

  HttpUploadEvent *clone() {
    return new HttpUploadEvent(*this);
  }
};

struct HttpPostMultipartFormEvent
  : public HttpEvent
{
    struct Part {
        enum Type {
            ImmediateValue,
            FilePath
        } type;
        string name;
        string content_type;
        string value;
        Part(const string &name,
             const string &content_type,
             const string &value,
             Type type = ImmediateValue)
          : name(name),
            content_type(content_type),
            value(value),
            type(type)
        {}
    };
    vector<Part> parts;
    string destination_name;

    HttpPostMultipartFormEvent(string destination_name, string token,
                               string session_id = string(),
                               const string &sync_ctx_id = string())
      : HttpEvent(MultiPartForm, session_id,token,sync_ctx_id),
        destination_name(destination_name)
    { }

    HttpPostMultipartFormEvent(const HttpPostMultipartFormEvent &src)
      : HttpEvent(MultiPartForm, src.session_id,src.token,src.sync_ctx_id,src.failover_idx,src.attempt),
        destination_name(src.destination_name),
        parts(src.parts)
    { }

    HttpPostMultipartFormEvent *clone() {
      return new HttpPostMultipartFormEvent(*this);
    }
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
  : public HttpEvent
{
  string data;
  string destination_name;
  map<string, string> additional_headers;

  HttpPostEvent(string destination_name, string data, string token,
                string session_id = string(),
                const string &sync_ctx_id = string())
    : HttpEvent(Post, session_id,token,sync_ctx_id),
      destination_name(destination_name),
      data(data)
  {}

  HttpPostEvent(string destination_name, string data,
                map<string, string> headers, string token,
                string session_id = string(),
                const string &sync_ctx_id = string())
    : HttpEvent(Post, session_id,token,sync_ctx_id),
      destination_name(destination_name),
      data(data),
      additional_headers(headers)
  {}

  HttpPostEvent(const HttpPostEvent &src)
    : HttpEvent(Post, src.session_id,src.token,src.sync_ctx_id,src.failover_idx,src.attempt),
      destination_name(src.destination_name),
      data(src.data),
      additional_headers(src.additional_headers)
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

struct HttpGetEvent
  : public HttpEvent
{
  string destination_name;
  string url;

  HttpGetEvent(const string& destination_name,
               const string& url, string token,
               const string &session_id = string())
    : HttpEvent(Get, session_id, token)
    , destination_name(destination_name)
    , url(url)
  {
  }

  HttpGetEvent(const HttpGetEvent &src)
    : HttpEvent(Get, src.session_id,src.token,src.sync_ctx_id,src.failover_idx,src.attempt),
      destination_name(src.destination_name)
    , url(src.url)
  {}
};

struct HttpGetResponseEvent
  : public AmEvent
{
  long int code;
  string token;
  string data;
  string mime_type;

  HttpGetResponseEvent(long int code, const string &data,
                        const string& mimetype, string token = string())
    : AmEvent(E_PLUGIN),
      code(code),
      data(data.c_str(), data.size()),
      mime_type(mimetype),
      token(token)
    {}
};

struct HttpTriggerSyncContext
  : public AmEvent
{
  string sync_ctx_id;
  int quantity;

  HttpTriggerSyncContext(string &ctx_id, int quantity)
    : AmEvent(HttpEvent::TriggerSyncContext),
      sync_ctx_id(ctx_id),
      quantity(quantity)
  {}
};

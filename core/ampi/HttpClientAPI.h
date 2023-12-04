#pragma once

#include "AmEvent.h"
#include "sys/time.h"

#define HTTP_EVENT_QUEUE "http"

struct HttpEvent
  : public AmEvent
{
    enum Type {
        Unknown = -1,
        Upload = 0,
        Post,
        MultiPartForm,
        Get,
        Multi,
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

    virtual ~HttpEvent() {}

    static Type str2type(const string& str) {
        if(str == "get") return Get;
        if(str == "post") return Post;
        if(str == "upload") return Upload;
        if(str == "multipart") return MultiPartForm;
        return Unknown;
    }

    virtual HttpEvent *http_clone() const = 0;
};


struct HttpUploadEvent
  : public HttpEvent
{

    string file_path;
    string file_name;
    string destination_name;

    HttpUploadEvent(
        string destination_name, string file_name, string file_path, string token,
        string session_id = string(),
        const string &sync_ctx_id = string())
      : HttpEvent(Upload, session_id,token,sync_ctx_id),
        file_path(file_path),
        file_name(file_name),
        destination_name(destination_name)
    {}

    HttpUploadEvent(const HttpUploadEvent &src)
      : HttpEvent(Upload, src.session_id,src.token,src.sync_ctx_id,src.failover_idx,src.attempt),
        file_path(src.file_path),
        file_name(src.file_name),
        destination_name(src.destination_name)
    {}

    HttpEvent *http_clone() const override {
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
        Part(
            const string &name,
            const string &content_type,
            const string &value,
            Type type = ImmediateValue)
          : type(type),
            name(name),
            content_type(content_type),
            value(value)
        {}
    };
    vector<Part> parts;
    string destination_name;

    HttpPostMultipartFormEvent(
        string destination_name, string token,
        string session_id = string(),
        const string &sync_ctx_id = string())
      : HttpEvent(MultiPartForm, session_id,token,sync_ctx_id),
        destination_name(destination_name)
    {}

    HttpPostMultipartFormEvent(const HttpPostMultipartFormEvent &src)
      : HttpEvent(MultiPartForm, src.session_id,src.token,src.sync_ctx_id,src.failover_idx,src.attempt),
        parts(src.parts),
        destination_name(src.destination_name)
    {}

    HttpEvent *http_clone() const override {
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

    HttpPostEvent(
        string destination_name, string data, string token,
        string session_id = string(),
        const string &sync_ctx_id = string())
      : HttpEvent(Post, session_id,token,sync_ctx_id),
        data(data),
        destination_name(destination_name)
    {}

    HttpPostEvent(
        string destination_name, string data,
        map<string, string> headers, string token,
        string session_id = string(),
        const string &sync_ctx_id = string())
      : HttpEvent(Post, session_id,token,sync_ctx_id),
        data(data),
        destination_name(destination_name),
        additional_headers(headers)
    {}

    HttpPostEvent(const HttpPostEvent &src)
      : HttpEvent(Post, src.session_id,src.token,src.sync_ctx_id,src.failover_idx,src.attempt),
        data(src.data),
        destination_name(src.destination_name),
        additional_headers(src.additional_headers)
    {}

    HttpEvent *http_clone() const override {
        return new HttpPostEvent(*this);
    }
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
        token(token),
        data(data)
    {}
};

struct HttpGetEvent
  : public HttpEvent
{
    string destination_name;
    string url;

    HttpGetEvent(
        const string& destination_name,
        const string& url, string token,
        const string &session_id = string())
      : HttpEvent(Get, session_id, token),
        destination_name(destination_name),
        url(url)
    {}

    HttpGetEvent(const HttpGetEvent &src)
      : HttpEvent(Get, src.session_id,src.token,src.sync_ctx_id,src.failover_idx,src.attempt),
        destination_name(src.destination_name),
        url(src.url)
    {}

    HttpEvent *http_clone() const override {
        return new HttpGetEvent(*this);
    }
};

struct HttpGetResponseEvent
  : public AmEvent
{
    long int code;
    string token;
    string data;
    string mime_type;

    HttpGetResponseEvent(
        long int code, const string &data,
        const string& mimetype, string token = string())
      : AmEvent(E_PLUGIN),
        code(code),
        token(token),
        data(data.c_str(), data.size()),
        mime_type(mimetype)
    {}
};

struct HttpMultiEvent
  : public HttpEvent
{
    vector<std::unique_ptr<HttpEvent>> multi_events;

    HttpMultiEvent(
        const string& token = string(),
        const string &sync_ctx_id = string())
      : HttpEvent(Multi, string(), token, sync_ctx_id)
    {}

    HttpMultiEvent(const HttpMultiEvent &src)
      : HttpEvent(Multi, src.session_id,src.token,src.sync_ctx_id,src.failover_idx,src.attempt)
    {
        for(auto& e : src.multi_events)
            add_event(e->http_clone());
    }

    HttpEvent *http_clone() const override {
        return new HttpMultiEvent(*this);
    }

    void add_event(HttpEvent* event) {
        multi_events.emplace_back(event);
    }
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

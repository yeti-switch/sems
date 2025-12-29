#include "s3_client.h"
#include "s3_client_opt.h"
#include <AmEventDispatcher.h>

#include <curl/multi.h>
#include <s3/request.h>
#include <s3/request_context.h>

#define EPOLL_MAX_EVENTS 2048

enum RpcMethodId { MethodRunS3Request };

class S3ClientFactory : public AmDynInvokeFactory, public AmConfigFactory {
    S3ClientFactory(const string &name)
        : AmDynInvokeFactory(name)
        , AmConfigFactory(name)
    {
        S3Client::instance();
    }
    ~S3ClientFactory() { S3Client::dispose(); }

  public:
    DECLARE_FACTORY_INSTANCE(S3ClientFactory);

    AmDynInvoke *getInstance() { return S3Client::instance(); }
    int          onLoad() { return S3Client::instance()->onLoad(); }
    void         on_destroy() { S3Client::instance()->stop(); }

    int configure(const std::string &config) { return S3Client::instance()->configure(config); }

    int reconfigure(const std::string &config) { return S3Client::instance()->configure(config); }
};

EXPORT_PLUGIN_CLASS_FACTORY(S3ClientFactory);
EXPORT_PLUGIN_CONF_FACTORY(S3ClientFactory);
DEFINE_FACTORY_INSTANCE(S3ClientFactory, MOD_NAME);

S3Client *S3Client::_instance = 0;

S3Client *S3Client::instance()
{
    if (_instance == nullptr) {
        _instance = new S3Client();
    }
    return _instance;
}

S3Client::S3Client()
    : AmEventFdQueue(this)
    , ShutdownHandler(MOD_NAME, S3CLIENT_QUEUE)
    , s3ctx(0)
{
}

S3Client::~S3Client()
{
    if (s3ctx)
        S3_destroy_request_context(s3ctx);
    S3_deinitialize();
}

void cfg_error_callback(cfg_t *cfg, const char *fmt, va_list ap)
{
    char  buf[2048];
    char *s = buf;
    char *e = s + sizeof(buf);

    if (cfg->title) {
        s += snprintf(s, e - s, "%s:%d [%s/%s]: ", cfg->filename, cfg->line, cfg->name, cfg->title);
    } else {
        s += snprintf(s, e - s, "%s:%d [%s]: ", cfg->filename, cfg->line, cfg->name);
    }
    s += vsnprintf(s, e - s, fmt, ap);

    ERROR("%.*s", (int)(s - buf), buf);
}

int S3Client::configure(const std::string &cfg_)
{
    cfg_t *cfg = cfg_init(s3_client_opt, CFGF_NONE);
    if (!cfg)
        return -1;
    cfg_set_error_function(cfg, cfg_error_callback);

    switch (cfg_parse_buf(cfg, cfg_.c_str())) {
    case CFG_SUCCESS: break;
    case CFG_PARSE_ERROR:
        ERROR("configuration of module %s parse error", MOD_NAME);
        cfg_free(cfg);
        return -1;
    default:
        ERROR("unexpected error on configuration of module %s processing", MOD_NAME);
        cfg_free(cfg);
        return -1;
    }

    string missed_params;

    auto assignMandatoryStrParam = [&cfg, &missed_params](string &param, const char *key) {
        if (!cfg_size(cfg, key)) {
            if (!missed_params.empty())
                missed_params += ", ";
            missed_params += key;
        } else {
            param = cfg_getstr(cfg, key);
        }
    };

    assignMandatoryStrParam(config.host, PARAM_HOST_NAME);
    assignMandatoryStrParam(config.bucket, PARAM_BUCKET_NAME);
    assignMandatoryStrParam(config.access_key, PARAM_ACCESS_KEY_NAME);
    assignMandatoryStrParam(config.secret_key, PARAM_SECRET_KEY_NAME);

    if (!cfg_size(cfg, PARAM_SECURE_NAME)) {
        if (!missed_params.empty())
            missed_params += ", ";
        missed_params += PARAM_SECURE_NAME;
    } else {
        config.secure = cfg_getbool(cfg, PARAM_SECURE_NAME);
    }

    config.verify_host   = cfg_getbool(cfg, PARAM_VERIFY_HOST_NAME);
    config.verify_peer   = cfg_getbool(cfg, PARAM_VERIFY_PEER_NAME);
    config.verify_status = cfg_getbool(cfg, PARAM_VERIFY_ST_NAME);

    cfg_free(cfg);

    if (!missed_params.empty()) {
        ERROR("missed mandatory parameters: %s", missed_params.data());
        return -1;
    }

    return 0;
}

int S3Client::onLoad()
{
    if (init()) {
        ERROR("initialization error");
        return -1;
    }
    start();
    return 0;
}

void S3Client::run()
{
    int                ret;
    void              *p;
    bool               running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    setThreadName("s3client");

    AmEventDispatcher::instance()->addEventQueue(S3CLIENT_QUEUE, this);

    running = true;
    do {
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if (ret == -1 && errno != EINTR) {
            ERROR("epoll_wait: %s", strerror(errno));
        }

        if (ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            p                     = e.data.ptr;

            if (p == &curl_timer) {
                on_timer_event();
                s3_requests_perform();
            } else if (p == static_cast<AmEventFdQueue *>(this)) {
                processEvents();
            } else if (p == &stop_event) {
                stop_event.read();
                running = false;
                break;
            } else {
                on_socket_event(e.data.fd, e.events);
                s3_requests_perform();
            }
        }
    } while (running);

    AmEventDispatcher::instance()->delEventQueue(S3CLIENT_QUEUE);

    epoll_unlink(epoll_fd);
    close(epoll_fd);

    DBG("S3Client stopped");
}

void S3Client::on_stop()
{
    stop_event.fire();
    join();
}

int S3Client::init()
{
    S3_initialize(SEMS_APP_NAME, S3_INIT_ALL, "");
    if (S3StatusOK != S3_create_request_context(&s3ctx))
        return -1;

    if ((epoll_fd = epoll_create(10)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    init_curl(epoll_fd, s3ctx->curlm);
    epoll_link(epoll_fd, true);
    stop_event.link(epoll_fd, true);
    init_rpc();

    return 0;
}

void S3Client::dispose()
{
    if (_instance != nullptr) {
        delete _instance;
    }
    _instance = nullptr;
}

void S3Client::process(AmEvent *ev)
{
    switch (ev->event_id) {
    case JSONRPC_EVENT_ID:
        if (auto e = dynamic_cast<JsonRpcRequestEvent *>(ev))
            process_jsonrpc_request(*e);
        break;
    case E_SYSTEM:
    {
        if (AmSystemEvent *sys_ev = dynamic_cast<AmSystemEvent *>(ev)) {
            switch (sys_ev->sys_event) {
            case AmSystemEvent::ServerShutdown:            stop_event.fire(); break;
            case AmSystemEvent::GracefulShutdownRequested: onShutdownRequested(); break;
            case AmSystemEvent::GracefulShutdownCancelled: onShutdownCancelled(); break;
            default:                                       break;
            }
        }
    } break;
    default: process_s3_event(ev);
    }

    checkFinished();
}

void S3Client::s3_requests_perform()
{
    if (!s3ctx)
        return;
    int still_running = 0;
    S3_runonce_request_context(s3ctx, &still_running);
}

void S3Client::onS3GetFileInfo(S3GetFileInfo &e)
{
    s3_get_file_info(e.name, new S3RequestData(this, new S3GetFileInfo(e)));
}

void S3Client::onS3GetFilePart(S3GetFilePart &e)
{
    s3_get_file_part(e.name, e.version_id, e.start, e.size, new S3RequestData(this, new S3GetFilePart(e)));
}

void S3Client::set_opt_connection(CURL *curl)
{
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, config.verify_peer);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, config.verify_host);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, config.verify_status);
}

void S3Client::responseComplete(S3Status status, S3RequestData *data)
{
    if (data->event->event_id == S3Event::GetFileInfo) {
        S3GetFileInfo *info = dynamic_cast<S3GetFileInfo *>(data->event.get());
        S3Event       *ret;
        if (status != S3StatusOK) {
            ret = new S3FileError(info->name, data->response);
        } else {
            ret = new S3FileInfo(info->name, data->response);
        }
        AmEventDispatcher::instance()->post(info->sender_id, ret);
    } else if (data->event->event_id == S3Event::GetFilePart) {
        S3GetFilePart *part = dynamic_cast<S3GetFilePart *>(data->event.get());
        S3Event       *ret;
        if (status != S3StatusOK) {
            ret = new S3FileError(part->name, data->response);
        } else {
            uint64_t size  = data->response["size"].asLongLong();
            char    *data_ = new char[size], *pos = data_;
            for (unsigned int i = 0; i < data->response["data"].size(); i++) {
                ArgBlob *blob = data->response["data"][i].asBlob();
                memcpy(pos, blob->data, blob->len);
                pos += blob->len;
            }
            DBG("send s3 part (%s, %llu, %llu)", part->name.c_str(), part->start, size);
            ret = new S3FilePart(part->name, part->start, size, data_);
        }
        AmEventDispatcher::instance()->post(part->sender_id, ret);
    }
}

static S3Status responsePropertiesCallback(const S3ResponseProperties *, void *)
{
    return S3StatusOK;
}
static void responseCompleteCallback(S3Status status, const S3ErrorDetails *error, void *callbackData)
{
    S3RequestData *data = (S3RequestData *)callbackData;
    if (status != S3StatusOK) {
        AmArg data_;
        data_["s3_status"]        = status;
        data->response["message"] = (error && error->message) ? error->message : "";
        data->response["code"]    = 500;
        data->response["data"]    = data_;
    }
    if (data->client) {
        data->client->responseComplete(status, data);
    } else {
        postJsonRpcReply(*data->request.get(), data->response, status != S3StatusOK);
    }
    delete data;
}

static S3Status showObjectCallback(const S3ResponseProperties *properties, void *callbackData)
{
    S3RequestData *data             = (S3RequestData *)callbackData;
    data->response["size"]          = properties->contentLength;
    data->response["type"]          = properties->contentType ? properties->contentType : "";
    data->response["etag"]          = properties->eTag ? properties->eTag : "";
    data->response["version_id"]    = properties->versionId ? properties->versionId : "";
    data->response["last_modified"] = properties->lastModified;
    for (int i = 0; i < properties->metaDataCount; i++) {
        S3NameValue nv          = properties->metaData[i];
        data->response[nv.name] = nv.value;
    }
    return S3StatusOK;
}

static S3Status listBucketCallback(int, const char *, int contentsCount, const S3ListBucketContent *contents, int,
                                   const char **, void *callbackData)
{
    S3RequestData *data = (S3RequestData *)callbackData;
    for (int i = 0; i < contentsCount; i++) {
        char                       timebuf[256];
        const S3ListBucketContent *content = &(contents[i]);
        time_t                     t       = (time_t)content->lastModified;
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", gmtime(&t));
        AmArg _content;
        _content["last_modified"] = timebuf;
        _content["size"]          = content->size;
        _content["name"]          = content->key;
        data->response.push(_content);
    }

    return S3StatusOK;
}

static S3Status getObjectDataCallback(int bufferSize, const char *buffer, void *callbackData)
{
    S3RequestData *data = (S3RequestData *)callbackData;
    if (data->client) {
        data->response["data"].push(ArgBlob(buffer, bufferSize));
    }
    int size = 0;
    if (data->response.hasMember("size"))
        size = data->response["size"].asLongLong();
    data->response["size"] = size + bufferSize;
    return S3StatusOK;
}

static inline bool isArgNumber(const AmArg &arg)
{
    return isArgDouble(arg) || isArgInt(arg) || isArgLongLong(arg);
}

void S3Client::s3_get_file_info(const string &key, void *callbackData)
{
    S3BucketContext bucketContext;
    memset(&bucketContext, 0, sizeof(S3BucketContext));
    bucketContext.hostName        = config.host.c_str();
    bucketContext.bucketName      = config.bucket.c_str();
    bucketContext.protocol        = config.secure ? S3ProtocolHTTPS : S3ProtocolHTTP;
    bucketContext.uriStyle        = S3UriStylePath;
    bucketContext.accessKeyId     = config.access_key.c_str();
    bucketContext.secretAccessKey = config.secret_key.c_str();

    S3ResponseHandler showObjectHandler;
    showObjectHandler.completeCallback   = &responseCompleteCallback;
    showObjectHandler.propertiesCallback = &showObjectCallback;
    S3_head_object(&bucketContext, key.c_str(), s3ctx, &showObjectHandler, callbackData);
}

void S3Client::s3_get_file_part(const std::string &key, const std::string &version_id, uint64_t start, uint64_t size,
                                void *callbackData)
{
    S3BucketContext bucketContext;
    memset(&bucketContext, 0, sizeof(S3BucketContext));
    bucketContext.hostName        = config.host.c_str();
    bucketContext.bucketName      = config.bucket.c_str();
    bucketContext.protocol        = config.secure ? S3ProtocolHTTPS : S3ProtocolHTTP;
    bucketContext.uriStyle        = S3UriStylePath;
    bucketContext.accessKeyId     = config.access_key.c_str();
    bucketContext.secretAccessKey = config.secret_key.c_str();

    S3GetObjectHandler getObjectHandler;
    getObjectHandler.responseHandler.completeCallback   = &responseCompleteCallback;
    getObjectHandler.responseHandler.propertiesCallback = &responsePropertiesCallback;
    getObjectHandler.getObjectDataCallback              = &getObjectDataCallback;

    S3_get_object(&bucketContext, key.c_str(), version_id.empty() ? 0 : version_id.c_str(), 0, start, size, s3ctx,
                  &getObjectHandler, callbackData);
}

void S3Client::process_jsonrpc_request(JsonRpcRequestEvent &request)
{
    try {
        switch (request.method_id) {
        case MethodRunS3Request:
        {
            S3ListBucketHandler listBucketHandler;
            string              cmd = request.params[0].asCStr();
            if (cmd == "ls") {
                S3BucketContext bucketContext;
                memset(&bucketContext, 0, sizeof(S3BucketContext));
                bucketContext.hostName        = config.host.c_str();
                bucketContext.bucketName      = config.bucket.c_str();
                bucketContext.protocol        = config.secure ? S3ProtocolHTTPS : S3ProtocolHTTP;
                bucketContext.uriStyle        = S3UriStylePath;
                bucketContext.accessKeyId     = config.access_key.c_str();
                bucketContext.secretAccessKey = config.secret_key.c_str();

                listBucketHandler.responseHandler.completeCallback   = &responseCompleteCallback;
                listBucketHandler.responseHandler.propertiesCallback = &responsePropertiesCallback;
                listBucketHandler.listBucketCallback                 = &listBucketCallback;
                S3_list_bucket(&bucketContext, NULL, NULL, NULL, 0, s3ctx, &listBucketHandler,
                               new S3RequestData(request));
            } else if (cmd == "get") {
                if (request.params.size() < 2 || request.params.size() == 4 || !isArgCStr(request.params[1]))
                    throw AmSession::Exception(500, "absent or incorrect parameter. usage s3_client.request get <path> "
                                                    "[<versionId> [<byte_start> <byte_size>]]");
                long long byte_start = 0, byte_size = 0;
                string    key = request.params[1].asCStr();
                string    version;
                if (request.params.size() > 2) {
                    if (!isArgCStr(request.params[2]))
                        throw AmSession::Exception(500, "incorrect 3 parameter. usage s3_client.request get <path> "
                                                        "[<versionId> [<byte_start> <byte_size>]]");
                    version = request.params[2].asCStr();
                }
                if (request.params.size() > 3) {
                    if (isArgCStr(request.params[3]) && !str2longlong(request.params[3].asCStr(), byte_start))
                        throw AmSession::Exception(500, "incorrect 4 parameter. usage s3_client.request get <path> "
                                                        "[<versionId> [<byte_start> <byte_size>]]");
                    else if (isArgNumber(request.params[3]))
                        byte_start = request.params[3].asLongLong();
                    else
                        throw AmSession::Exception(500, "incorrect 4 parameter. usage s3_client.request get <path> "
                                                        "[<versionId> [<byte_start> <byte_size>]]");
                    if (isArgCStr(request.params[4]) && !str2longlong(request.params[4].asCStr(), byte_size))
                        throw AmSession::Exception(500, "incorrect 5 parameter. usage s3_client.request get <path> "
                                                        "[<versionId> [<byte_start> <byte_size>]]");
                    else if (isArgNumber(request.params[4]))
                        byte_start = request.params[4].asLongLong();
                    else
                        throw AmSession::Exception(500, "incorrect 5 parameter. usage s3_client.request get <path> "
                                                        "[<versionId> [<byte_start> <byte_size>]]");
                }
                s3_get_file_part(key, version, byte_start, byte_size, new S3RequestData(request));
            } else if (cmd == "show") {
                if (request.params.size() < 2)
                    throw AmSession::Exception(500,
                                               "absent or incorrect parameter. usage s3_client.request show <path>");
                string key = request.params[1].asCStr();
                s3_get_file_info(key, new S3RequestData(request));
            } else
                throw AmSession::Exception(500, "unsupport command. using `ls`, `get`, `show` command");
        } break;
        }
    } catch (const AmSession::Exception &ex) {
        AmArg ret;
        ret["message"] = ex.reason;
        ret["code"]    = ex.code;
        postJsonRpcReply(request, ret, true);
    }
}

void S3Client::process_s3_event(AmEvent *ev)
{
    switch (ev->event_id) {
    case S3Event::GetFileInfo:
    {
        if (S3GetFileInfo *e = dynamic_cast<S3GetFileInfo *>(ev))
            onS3GetFileInfo(*e);
    } break;
    case S3Event::GetFilePart:
    {
        if (S3GetFilePart *e = dynamic_cast<S3GetFilePart *>(ev))
            onS3GetFilePart(*e);
    } break;
    }
}

void S3Client::init_rpc_tree()
{
    auto &show = reg_leaf(root, "show");
    reg_method(show, "config", "config dump", "", &S3Client::showConfig, this);
    reg_method(root, "request", "send s3 request", "", &S3Client::runS3Request, this);
}

uint64_t S3Client::get_active_tasks_count()
{
    return 0;
}

bool S3Client::runS3Request(const string &connection_id, const AmArg &request_id, const AmArg &params)
{
    if (!params.size() || !isArgCStr(params[0])) {
        throw AmSession::Exception(500, "usage: s3client.request <command> <params>");
    }

    postEvent(new JsonRpcRequestEvent(connection_id, request_id, false, MethodRunS3Request, params));

    return true;
}

void S3Client::showConfig(const AmArg &, AmArg &ret)
{
    ret["host"]       = config.host;
    ret["bucket"]     = config.bucket;
    ret["access_key"] = config.access_key;
    ret["secret_key"] = config.secret_key;
    ret["secure"]     = config.secure;
    if (config.secure) {
        ret["verify_host"]   = config.verify_host;
        ret["verify_peer"]   = config.verify_peer;
        ret["verify_status"] = config.verify_status;
    }
}

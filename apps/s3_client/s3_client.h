#pragma once

#include <AmApi.h>
#include <AmEventFdQueue.h>
#include <RpcTreeHandler.h>
#include <ampi/S3ClientApi.h>
#include <ShutdownHandler.h>

#include "CurlMultiHandler.h"

#include <string>
#include <map>
#include <s3/libs3.h>
using std::string;
using std::map;

#define MOD_NAME        "s3_client"

class S3Client;

struct S3RequestData
{
    S3Client* client;
    auto_ptr<S3Event> event;
    auto_ptr<JsonRpcRequestEvent> request;

    AmArg response;

    S3RequestData(S3Client* client,
                  S3Event* event_)
    : client(client)
    , event(event_)
    , request(0){}
    S3RequestData(const JsonRpcRequestEvent& event) : client(0), event(0), request(new JsonRpcRequestEvent(event)){}
};

class S3Client
: public AmThread
, public AmEventFdQueue
, public AmEventHandler
, public RpcTreeHandler<S3Client>
, public CurlMultiHandler
, public ShutdownHandler
{
    friend class S3ClientFactory;
    static S3Client* _instance;

    AmEventFd stop_event;
    AmCondition<bool> stopped;
    int epoll_fd;
    S3RequestContext* s3ctx;
    struct {
        string host;
        string access_key;
        string secret_key;
        string bucket;
        bool secure;
        bool verify_peer;
        bool verify_host;
        bool verify_status;
    } config;

protected:
    int init();
    void s3_requests_perform();

    void onS3GetFileInfo(S3GetFileInfo& e);
    void s3_get_file_info(const string& key, void* callbackData);
    void onS3GetFilePart(S3GetFilePart& e);
    void s3_get_file_part(const string& key, uint64_t start, uint64_t size, void* callbackData);

    void set_opt_connection(CURL * curl) override;
public:
    void responseComplete(S3Status status, S3RequestData* data);
public:
    S3Client();
    ~S3Client();

    static S3Client* instance();
    static void dispose();
    AmDynInvoke* getInstance() { return static_cast<AmDynInvoke*>(instance()); }

    int onLoad();
    int configure(const string& config);

    void run() override;
    void on_stop() override;

    void init_rpc_tree() override;

    void process(AmEvent* ev) override;
    void process_jsonrpc_request(JsonRpcRequestEvent &request);
    void process_s3_event(AmEvent * ev);

    uint64_t get_active_tasks_count() override;

    rpc_handler showConfig;
    async_rpc_handler runS3Request;
};

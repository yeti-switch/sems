#pragma once

#include "AmArg.h"
#include "ampi/HttpClientAPI.h"

#include <map>
#include <string>
#include <list>
#include <confuse.h>
using std::string;
using std::list;

class HttpClient;
class CurlConnection;

class DestinationAction {
public:
    enum HttpAction {
        Unknown = -1,
        Nothing = 0,
        Remove,
        Move,
        Requeue
    };
    DestinationAction(): action(Unknown), need_data(false) {}

    int parse(const string &default_action, cfg_t* cfg);
    void perform() const;
    void set_path(const string& path);

    bool requeue() const { return action==Requeue; }
    bool has_data() const { return need_data; }
    const string &data() const { return action_data; }
    const string &str() const { return action_str; }

    static HttpAction str2Action(const string& action);
private:
    HttpAction action;
    string action_str;
    string action_data;
    string file_path;
    string file_basename;
    bool need_data;
};

class HttpCodesMap {
    bool codes[1000];
  public:
    HttpCodesMap();
    int parse(cfg_t* cfg);
    void dump(AmArg &ret) const;
    bool operator ()(long int code) const;
};

struct DefaultValues {
    unsigned int resend_queue_max;
    unsigned int resend_connection_limit;
    unsigned int connection_limit;
};

struct HttpDestination {

    HttpDestination(const string &name);
    ~HttpDestination();

    HttpCodesMap succ_codes;
    DestinationAction succ_action;
    DestinationAction fail_action;
    DestinationAction finish_action;

    string content_type;

    int parse(const string &name, cfg_t *cfg, const DefaultValues& values, bool is_auth);

    bool need_requeue() const { return fail_action.requeue(); }

    string action_data;

    enum Mode {
        Unknown,
        Put,
        Post,
        Get
    } mode;
    string mode_str;

    /** this destination is used for auth purposes */
    enum AuthType {
        AuthType_Unknown,
        AuthType_Firebase_oauth2,
        AuthType_s3,
    } auth_type;
    string auth_type_str;

    bool is_auth_destination;
    string key_file;
    string key_data;
    string access_token;
    string jwt_kid;
    string jwt_iss;
    int token_lifetime;
    timeval token_created_at;
    int     expires;
    string access_key;
    string secret_key;

    bool http2_tls;
    string auth_required; /** this destination requires the specified authentication */
    string auth_usrpwd;   /** this destination uses username:password authentication */
    string certificate;
    string certificate_key;
    vector<string> url;
    vector<string> http_headers;
    string source_address;
    size_t max_failover_idx;
    unsigned int attempts_limit;
    unsigned int resend_queue_max;
    unsigned int resend_connection_limit;
    unsigned int connection_limit;
    unsigned int min_file_size;
    unsigned int max_reply_size;

    list<HttpEvent*> events;
    AtomicCounter& count_failed_events;
    AtomicCounter& count_connection;
    AtomicCounter& resend_count_connection;
    AtomicCounter& count_pending_events;
    AtomicCounter& requests_processed;
    AtomicCounter& requests_failed;

    string succ_codes_str;

    void on_finish(bool failed, const string &response);
    int post_upload(const string &file_path, const string &file_basename, bool failed) const;
    int post_upload(bool failed) const;

    void dump(const string &key) const;
    void dump(const string &key, AmArg &ret) const;
    static Mode str2Mode(const string& mode);
    static AuthType str2AuthType(const string& type);

    void addEvent(HttpEvent* event);
    void credentials_refresh(HttpClient* client, const string &name);
    void auth_on_timer_event(HttpClient* client, const string &name);
    void send_failed_events(HttpClient* client);
    void send_postponed_events(HttpClient* client);
    bool check_queue();
    void showStats(AmArg &ret);
};

class HttpDestinationsMap
  : public std::map<string,HttpDestination>
{
    int configure_destination(const string &name, cfg_t *cfg, const DefaultValues& values, bool is_auth);
    int configure_destination_group(const string &name, cfg_t *cfg);
  public:

    int configure(cfg_t *cfg, DefaultValues &values);
    void dump();
    void dump(AmArg &ret);

    bool need_requeue();
};


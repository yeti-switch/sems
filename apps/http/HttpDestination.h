#pragma once

#include "AmArg.h"
#include "HttpClientAPI.h"

#include <map>
#include <string>
#include <list>
#include <confuse.h>
using std::string;
using std::list;

#include "curl/curl.h"

class HttpClient;

class DestinationAction {
public:
    enum HttpAction {
        Unknown = -1,
        Nothing = 0,
        Remove,
        Move,
        Requeue
    };
    DestinationAction(): need_data(false) {}

    int parse(const string &default_action, cfg_t* cfg);
    int perform(const string &file_path, const string &file_basename) const;
    int perform() const;

    bool requeue() const { return action==Requeue; }
    bool has_data() const { return need_data; }
    const string &data() const { return action_data; }
    const string &str() const { return action_str; }

    static HttpAction str2Action(const string& action);
private:
    HttpAction action;
    string action_str;
    string action_data;
    bool need_data;
};

class HttpCodesMap {
    bool codes[1000];
  public:
    HttpCodesMap();
    int parse(cfg_t* cfg);
    bool operator ()(long int code) const;
};

struct DefaultValues {

    unsigned int resend_queue_max;
    unsigned int resend_connection_limit;
    unsigned int connection_limit;
};

struct HttpDestination {

    HttpDestination(){}
    ~HttpDestination();

    HttpCodesMap succ_codes;
    DestinationAction succ_action;
    DestinationAction fail_action;

    string content_type;

    int parse(const string &name, cfg_t *cfg, const DefaultValues& values);

    bool need_requeue() const { return fail_action.requeue(); }

    string action_data;

    enum Mode {
        Unknown,
        Put,
        Post
    } mode;
    string mode_str;

    vector<string> url;
    size_t max_failover_idx;
    unsigned int attempts_limit;
    unsigned int resend_queue_max;
    unsigned int resend_connection_limit;
    unsigned int connection_limit;

    list<HttpEvent*> events;
    unsigned int count_failed_events;
    unsigned int count_connection;
    unsigned int resend_count_connection;

    string succ_codes_str;

    int post_upload(const string &file_path, const string &file_basename, bool failed) const;
    int post_upload(bool failed) const;

    void dump(const string &key) const;
    void dump(const string &key, AmArg &ret) const;
    static Mode str2Mode(const string& mode);

    void addEvent(HttpEvent* event);
    void send_failed_events(HttpClient* client);
    void send_postponed_events(HttpClient* client);
    bool check_queue();
    void showStats(AmArg &ret);
};

class HttpDestinationsMap
  : public std::map<string,HttpDestination>
{
    int configure_destination(const string &name, cfg_t *cfg, const DefaultValues& values);
  public:

    int configure(cfg_t *cfg, const DefaultValues& values);
    void dump();
    void dump(AmArg &ret);

    bool need_requeue();
};


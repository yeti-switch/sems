#pragma once

#include "AmArg.h"

#include <map>
#include <string>
#include <confuse.h>
using std::string;

#include "curl/curl.h"

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

struct HttpDestination {

    HttpCodesMap succ_codes;
    DestinationAction succ_action;
    DestinationAction fail_action;

    string content_type;

    int parse(const string &name, cfg_t *cfg);

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

    string succ_codes_str;

    int post_upload(const string &file_path, const string &file_basename, bool failed) const;
    int post_upload(bool failed) const;

    void dump(const string &key) const;
    void dump(const string &key, AmArg &ret) const;
    static Mode str2Mode(const string& mode);
};

class HttpDestinationsMap
  : public std::map<string,HttpDestination>
{
    int configure_destination(const string &name, cfg_t *cfg);
  public:

    int configure(cfg_t *cfg);
    void dump();
    void dump(AmArg &ret);

    bool need_requeue();
};


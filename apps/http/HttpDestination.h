#pragma once

#include "AmConfigReader.h"
#include "AmArg.h"

#include <map>
#include <string>
using std::string;

#include "curl/curl.h"

class DestinationAction {
    enum HttpAction {
        Nothing = 0,
        Remove,
        Move,
        Requeue
    } action;
    string action_str;
    string action_data;
    bool need_data;
  public:
    DestinationAction(): need_data(false) {}

    int parse(const string &prefix, const string &default_action, AmConfigReader &cfg);
    int perform(const string &file_path, const string &file_basename) const;
    int perform() const;

    bool requeue() const { return action==Requeue; }
    bool has_data() const { return need_data; }
    const string &data() const { return action_data; }
    const string &str() const { return action_str; }
};

struct HttpDestination {

    DestinationAction succ_action;
    DestinationAction fail_action;

    string content_type;

    int parse(const string &name, AmConfigReader &cfg);

    bool need_requeue() const { return fail_action.requeue(); }

    string action_data;

    enum Mode {
        Put,
        Post
    } mode;
    string mode_str;

    string url;

    int post_upload(const string &file_path, const string &file_basename, bool failed) const;
    int post_upload(bool failed) const;

    void dump(const string &key) const;
    void dump(const string &key, AmArg &ret) const;
};

class HttpDestinationsMap
  : public std::map<string,HttpDestination>
{
    int configure_destination(const string &name, AmConfigReader &cfg);
  public:

    int configure(AmConfigReader &cfg);
    void dump();
    void dump(AmArg &ret);

    bool need_requeue();
};


#include "HttpDestination.h"
#include "http_client_cfg.h"
#include "AmLcConfig.h"
#include "AmUtils.h"
#include "log.h"
#include "defs.h"

#include <algorithm>
#include <vector>
using std::vector;
#include <cstdio>

int DestinationAction::parse(const string &default_action, cfg_t* cfg)
{
    if(!cfg_size(cfg, PARAM_ACTION_NAME)) {
        action_str = default_action;
    } else {
        action_str = cfg_getstr(cfg, PARAM_ACTION_NAME);
    }

    action = str2Action(action_str);
    if(action == Move){
        need_data = true;
    } else if(action == Unknown){
        ERROR("uknown post-upload action: %s", action_str.c_str());
        return -1;
    }

    action_data = cfg_getstr(cfg, PARAM_ACTION_ARGS_NAME);
    if(need_data && action_data.empty()){
        ERROR("%s: missed action_arg for post upload action: %s",
              cfg->title, action_str.c_str());
        return -1;
    }

    return 0;
}

int DestinationAction::perform(const string &file_path, const string &file_basename) const
{
    switch(action){
    case Nothing: break;
    case Remove:
        if(file_path.empty()) break;
        CDBG("remove '%s' after upload",file_path.c_str());
        if(0!=std::remove(file_path.c_str())){
            ERROR("can't remove '%s': %d",file_path.c_str(),errno);
        }
        break;
    case Move: {
        if(file_path.empty()) break;
        string destination_path = action_data + "/" + file_basename;
        CDBG("move  '%s'->'%s' after upload",file_path.c_str(),destination_path.c_str());
        if(0!=std::rename(file_path.c_str(),destination_path.c_str())){
            ERROR("can't move '%s'->'%s': %d",file_path.c_str(),destination_path.c_str(),errno);
        }
    } break;
    case Requeue:
        return 1;
    default:
        break;
    }
    return 0;
}

int DestinationAction::perform() const
{
    switch(action){
    case Requeue:
        return 1;
        break;
    default:
        break;
    }
    return 0;
}

DestinationAction::HttpAction DestinationAction::str2Action(const string& action)
{
    if(action==ACTION_REMOVE_VALUE){
        return Remove;
    } else if(action==ACTION_NOTHING_VALUE){
       return Nothing;
    } else if(action==ACTION_MOVE_VALUE){
        return Move;
    } else if(action==ACTION_REQUEUE_VALUE) {
        return Requeue;
    } else {
        return Unknown;
    }
}

HttpCodesMap::HttpCodesMap()
{
    bzero(codes,sizeof(codes));
}

int HttpCodesMap::parse(cfg_t* cfg)
{
    if(!cfg_size(cfg, PARAM_SUCCESS_CODES_NAME)) {
        //2xx
        memset(codes+200,true,sizeof(bool)*100);
        return 0;
    }

    for(unsigned int i = 0; i < cfg_size(cfg, PARAM_SUCCESS_CODES_NAME); i++) {
        string mask = cfg_getnstr(cfg, PARAM_SUCCESS_CODES_NAME, i);
        if(mask.find('x')!=string::npos) {
            string mins =  mask, maxs = mask;
            int min,max;
            std::replace(mins.begin(),mins.end(),'x','0');
            std::replace(maxs.begin(),maxs.end(),'x','9');
            if(!str2int(mins,min)) {
                ERROR("can't convert bottom border value %s for mask %s to int.",
                    mins.c_str(),mask.c_str());
                return -1;
            }
            if(!str2int(maxs,max)) {
                ERROR("can't convert upper border value %s for mask %s to int",
                    maxs.c_str(),mask.c_str());
                return -1;
            }
            for(int i = min; i <= max; i++)
                codes[i] = true;
        } else {
            int i;
            if(!str2int(mask,i)) {
                ERROR("can't convert mask %s to int",
                    mask.c_str());
                return -1;
            }
            codes[i] = true;
        }
    }
    return 0;
}

bool HttpCodesMap::operator ()(long int code) const
{
    if(code > 0 && code < 1000) return codes[code];
    else return false;
}

int HttpDestination::parse(const string &name, cfg_t *cfg)
{
    AmLcConfig::GetInstance().getMandatoryParameter(cfg, PARAM_MODE_NAME, mode_str);
    mode = str2Mode(mode_str);
    if(mode == Unknown) {
        ERROR("%s: uknown mode: %s",name.c_str(),mode_str.c_str());
        return -1;
    }

    for(unsigned int i = 0; i < cfg_size(cfg, PARAM_URL_NAME); i++) {
        string url_ = cfg_getnstr(cfg, PARAM_URL_NAME, i);
        url.push_back(url_);
    }
    if(url.empty()){
        ERROR("missed url for destination %s",name.c_str());
        return -1;
    }
    max_failover_idx = url.size()-1;

    attempts_limit = cfg_getint(cfg, PARAM_REQUEUE_LIMIT_NAME);

    if(succ_codes.parse(cfg)) {
        ERROR("can't parse succ codes map");
        return -1;
    }

    if(!cfg_size(cfg, SECTION_ON_SUCCESS_NAME)) {
        ERROR("absent post_upload action");
        return -1;
    }

    cfg_t* saction = cfg_getsec(cfg, SECTION_ON_SUCCESS_NAME);
    if(succ_action.parse(ACTION_REMOVE_VALUE, saction)) {
        ERROR("can't parse post_upload action");
        return -1;
    }

    if(!cfg_size(cfg, SECTION_ON_FAIL_NAME)) {
        ERROR("absent failed_upload action");
        return -1;
    }

    cfg_t* faction = cfg_getsec(cfg, SECTION_ON_FAIL_NAME);
    if(fail_action.parse(ACTION_REMOVE_VALUE, faction)) {
        ERROR("can't parse failed_upload action");
        return -1;
    }

    if(succ_action.requeue()){
        ERROR("forbidden action 'requeue' for succ action");
        return -1;
    }

    if(mode==Post) {
        content_type = cfg_getstr(cfg, "content_type");
    }

    return 0;
}

void HttpDestination::dump(const string &key) const
{
    string url_list;
    for(auto& url_ : url) {
        if(!url_list.empty())
            url_list += ",";
        url_list += url_;
    }
    DBG("destination %s: %s %s, post_upload = %s %s, failed_upload = %s %s",
        key.c_str(),
        mode_str.c_str(),url_list.c_str(),
        succ_action.str().c_str(), succ_action.data().c_str(),
        fail_action.str().c_str(), fail_action.data().c_str());
}

void HttpDestination::dump(const string &key, AmArg &ret) const
{
    string url_list;
    for(auto& url_ : url) {
        if(!url_list.empty())
            url_list += ",";
        url_list += url_;
    }
    ret["url"] = url_list;
    ret["mode"] = mode_str.c_str();
    ret["action"] = succ_action.str();
    if(succ_action.has_data()){
        ret["action_data"] = succ_action.data();
    }
    ret["failed_action"] = fail_action.str();
    if(fail_action.has_data()){
        ret["failed_action_data"] = fail_action.str();
    }
    if(mode==Post && !content_type.empty()) {
        ret["content_type"] = content_type;
    }
}


HttpDestination::Mode HttpDestination::str2Mode(const string& mode)
{
    if(mode == MODE_PUT_VALUE) {
        return Put;
    } else if(mode == MODE_POST_VALUE) {
        return Post;
    }
    return Unknown;
}

int HttpDestination::post_upload(const string &file_path, const string &file_basename, bool failed) const
{
    int requeue = 0;

    if(!failed) {
        succ_action.perform(file_path,file_basename);
    } else {
        requeue = fail_action.perform(file_path,file_basename);
    }

    return requeue;
}

int HttpDestination::post_upload(bool failed) const
{
    int requeue = 0;

    if(!failed) {
        succ_action.perform();
    } else {
        requeue = fail_action.perform();
    }

    return requeue;
}

int HttpDestinationsMap::configure_destination(const string &name, cfg_t *cfg)
{
    HttpDestination d;
    if(d.parse(name,cfg)){
        return -1;
    }
    std::pair<HttpDestinationsMap::iterator,bool> ret;
    ret = insert(std::pair<string, HttpDestination>(name,d));
    if(ret.second==false){
        ERROR("duplicate upload destination: %s",name.c_str());
        return -1;
    }
    return 0;
}

int HttpDestinationsMap::configure(cfg_t * cfg)
{
    for(unsigned int i = 0; i < cfg_size(cfg, SECTION_DIST_NAME); i++) {
        cfg_t *dist = cfg_getnsec(cfg, SECTION_DIST_NAME, i);
        if(configure_destination(dist->title, dist)) {
            ERROR("can't configure destination %s",dist->title);
            return -1;
        }
    }

    return 0;
}

void HttpDestinationsMap::dump()
{
    for(HttpDestinationsMap::const_iterator i =
        begin(); i!=end();i++)
    i->second.dump(i->first);
}

void HttpDestinationsMap::dump(AmArg &ret)
{
    ret.assertStruct();
    for(HttpDestinationsMap::const_iterator i =
        begin(); i!=end();i++)
    i->second.dump(i->first,ret[i->first]);
}

bool HttpDestinationsMap::need_requeue()
{
    for(HttpDestinationsMap::const_iterator i =
        begin(); i!=end();i++)
    {
        if(i->second.need_requeue())
            return true;
    }
    return false;
}


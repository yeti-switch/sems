#include "HttpDestination.h"
#include "defs.h"

#include "AmUtils.h"
#include "log.h"

#include <algorithm>

#include <vector>
using std::vector;

#include <cstdio>

int DestinationAction::parse(const string &prefix, const string &default_action, AmConfigReader &cfg)
{
    action_str = cfg.getParameter(prefix + "_action",default_action);

    if(action_str=="remove"){
        action = Remove;
    } else if(action_str=="nothing"){
        action = Nothing;
    } else if(action_str=="move"){
        action = Move;
        need_data = true;
    } else if(action_str=="requeue") {
        action = Requeue;
    } else {
        ERROR("uknown post-upload action: %s", action_str.c_str());
        return -1;
    }

    action_data = cfg.getParameter(prefix + "_action_arg");
    if(need_data && action_data.empty()){
        ERROR("%s: missed action_arg for post upload action: %s",
              prefix.c_str(),action_str.c_str());
        return -1;
    }

    return 0;
}

int DestinationAction::perform(const string &file_path, const string &file_basename) const
{
    switch(action){
    case Nothing: break;
    case Remove:
        CDBG("remove '%s' after upload",file_path.c_str());
        if(0!=std::remove(file_path.c_str())){
            ERROR("can't remove '%s': %d",file_path.c_str(),errno);
        }
        break;
    case Move: {
        string destination_path = action_data + "/" + file_basename;
        CDBG("move  '%s'->'%s' after upload",file_path.c_str(),destination_path.c_str());
        if(0!=std::rename(file_path.c_str(),destination_path.c_str())){
            ERROR("can't move '%s'->'%s': %d",file_path.c_str(),destination_path.c_str(),errno);
        }
    } break;
    case Requeue:
        return 1;
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

HttpCodesMap::HttpCodesMap()
{
    bzero(codes,sizeof(codes));
}

int HttpCodesMap::parse(const string &name, AmConfigReader &cfg)
{
    if(!cfg.hasParameter(name)) {
        //2xx
        memset(codes+200,true,sizeof(bool)*100);
        return 0;
    }

    string mask_list_str = cfg.getParameter(name);
    vector<string> mask_list = explode(mask_list_str,",");
    for(const string & mask : mask_list) {
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

int HttpDestination::parse(const string &name, AmConfigReader &cfg)
{
    string mode_str = cfg.getParameter(name + "_mode","put");
    if(mode_str.empty()) {
        ERROR("missed upload mode for destination %s",name.c_str());
        return -1;
    }
    if(mode_str=="put") {
        mode = Put;
    } else if(mode_str=="post") {
        mode = Post;
    } else {
        ERROR("%s: uknown mode: %s",name.c_str(),mode_str.c_str());
        return -1;
    }

    url_list = cfg.getParameter(name + "_url");
    if(url_list.empty()){
        ERROR("missed url for destination %s",name.c_str());
        return -1;
    }
    url = explode(url_list,",");
    max_failover_idx = url.size()-1;

    attempts_limit = cfg.getParameterInt(name + "_requeue_limit",0);

    if(succ_codes.parse(name+"_succ_codes",cfg)) {
        ERROR("can't parse succ codes map");
        return -1;
    }

    if(succ_action.parse(name + "_succ","remove",cfg)){
        ERROR("can't parse post_upload action");
        return -1;
    }
    if(succ_action.requeue()){
        ERROR("forbidden action 'requeue' for succ action");
        return -1;
    }

    if(fail_action.parse(name + "_fail","nothing",cfg)){
        ERROR("can't parse failed_upload action");
        return -1;
    }

    if(mode==Post) {
        content_type = cfg.getParameter(name + "_content_type");
    }

    return 0;
}

void HttpDestination::dump(const string &key) const
{
    DBG("destination %s: %s %s, post_upload = %s %s, failed_upload = %s %s",
        key.c_str(),
        mode_str.c_str(),url_list.c_str(),
        succ_action.str().c_str(), succ_action.data().c_str(),
        fail_action.str().c_str(), fail_action.data().c_str());
}

void HttpDestination::dump(const string &key, AmArg &ret) const
{
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

int HttpDestinationsMap::configure_destination(const string &name, AmConfigReader &cfg)
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

int HttpDestinationsMap::configure(AmConfigReader &cfg)
{
    vector<string> destinations = explode(cfg.getParameter("destinations",""),",",false);
    for(vector<string>::const_iterator d = destinations.begin();
        d!= destinations.end(); d++)
    {
        if(configure_destination(*d,cfg)){
            ERROR("can't configure destination %s",d->c_str());
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


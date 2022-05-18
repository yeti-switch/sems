/*
 * Copyright (C) 2002-2003 Fhg Fokus
 * Copyright (C) 2006 iptego GmbH
 *
 * This file is part of SEMS, a free SIP media server.
 *
 * SEMS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version. This program is released under
 * the GPL with the additional exemption that compiling, linking,
 * and/or using OpenSSL is allowed.
 *
 * For a license to use the SEMS software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * SEMS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "AmPlugIn.h"
#include "AmApi.h"
#include "AmUtils.h"
#include "AmSipDispatcher.h"
#include "AmLcConfig.h"
#include "sip/defs.h"

#include "amci/amci.h"
#include "amci/codecs.h"
#include "log.h"

#include <sys/types.h>
#include <dirent.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>

#include <set>
#include <vector>
#include <algorithm>
#include "AmSdp.h"
using std::set;

static unsigned int pcm16_bytes2samples(long h_codec, unsigned int num_bytes)
{
  return num_bytes / 2;
}

static unsigned int pcm16_samples2bytes(long h_codec, unsigned int num_samples)
{
  return num_samples * 2;
}

static unsigned int tevent_bytes2samples(long h_codec, unsigned int num_bytes)
{
  return num_bytes;
}

static unsigned int tevent_samples2bytes(long h_codec, unsigned int num_samples)
{
  return num_samples;
}

amci_codec_t _codec_pcm16 = { 
  CODEC_PCM16,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  pcm16_bytes2samples,
  pcm16_samples2bytes
};

amci_codec_t _codec_tevent = { 
  CODEC_TELEPHONE_EVENT,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  tevent_bytes2samples,
  tevent_samples2bytes
};

#define tevent_payload_initializer(RATE) \
    { -1, "telephone-event", 800, RATE, -1, CODEC_TELEPHONE_EVENT, -1 }

static amci_payload_t _payload_tevent_8 = tevent_payload_initializer(8000);
static amci_payload_t _payload_tevent_16 = tevent_payload_initializer(16000);
static amci_payload_t _payload_tevent_24 = tevent_payload_initializer(24000);
static amci_payload_t _payload_tevent_32 = tevent_payload_initializer(32000);
static amci_payload_t _payload_tevent_48 = tevent_payload_initializer(48000);

AmPlugIn* AmPlugIn::_instance = nullptr;

AmPlugIn::AmPlugIn()
  : dynamic_pl(DYNAMIC_PAYLOAD_TYPE_START)
    //ctrlIface(NULL)
{
}


static void delete_plugin_factory(std::pair<string, AmPluginFactory*> pf)
{
  DBG("decreasing reference to plug-in factory: %s", pf.first.c_str());
  dec_ref(pf.second);
}

AmPlugIn::~AmPlugIn()
{
  /*for(std::map<std::string,AmLoggingFacility*>::iterator it = name2logfac.begin();
      it != name2logfac.end(); it++){
    // register for receiving logging messages
    unregister_log_hook(it->second);
  }*/
  std::for_each(name2logfac.begin(), name2logfac.end(), delete_plugin_factory);
  std::for_each(name2di.begin(), name2di.end(), delete_plugin_factory);
  std::for_each(name2seh.begin(), name2seh.end(), delete_plugin_factory);
  std::for_each(plugins_objects.begin(), plugins_objects.end(), delete_plugin_factory);
  std::for_each(name2config.begin(), name2config.end(), delete_plugin_factory);

  // if _DEBUG is set do not unload shared libs to allow better debugging
#ifndef _DEBUG
//  for(vector<void*>::iterator it=dlls.begin();it!=dlls.end();++it)
    //dlclose(*it);
#endif
}

void AmPlugIn::dispose()
{
  if (_instance) {
    delete _instance;
  }
}

AmPlugIn* AmPlugIn::instance()
{
  if(!_instance)
    _instance = new AmPlugIn();

  return _instance;
}

void AmPlugIn::init() {
    for(const auto &p: AmConfig.exclude_payloads)
        excluded_payloads.emplace(p);

    DBG("adding built-in codecs...");

    addCodec(&_codec_pcm16);
    addCodec(&_codec_tevent);
    addPayload(&_payload_tevent_8);
    addPayload(&_payload_tevent_16);
    addPayload(&_payload_tevent_24);
    addPayload(&_payload_tevent_32);
    addPayload(&_payload_tevent_48);
}

int AmPlugIn::load(const string& directory, const std::vector<std::string>& plugins)
{
    int err=0;

    for (auto plugin_file : plugins) {
        if (plugin_file == "sipctrl") {
            WARN("sipctrl is integrated into the core, loading sipctrl "
                 "module is not necessary any more");
            WARN("please update your configuration to not load sipctrl module");
            continue;
        }

        if(plugin_file.find(".so",plugin_file.length()-3) == string::npos )
            plugin_file+=".so";

        plugin_file = directory + "/"  + plugin_file;

        DBG("loading %s...",plugin_file.c_str());

        if((err = loadPlugIn(plugin_file, plugin_file)) < 0 ) {
            ERROR("while loading plug-in '%s'",plugin_file.c_str());
            // be strict here: if plugin not loaded, stop!
            return err;
        }
    }

    DBG("AmPlugIn: modules loaded.");

    return 0;
}

int AmPlugIn::initPlugins()
{
    for(auto &plugin : plugins_objects) {

        if(name2logfac.end() != std::find_if(
            name2logfac.begin(),name2logfac.end(),
            [&plugin](auto &it) {
                return it.second == plugin.second;
            }
        )) {
            //ignore logging plugins
            continue;
        }

        DBG("initialize plug-in %s", plugin.first.data());

        int err = plugin.second->onLoad();
        if(err)
            return err;
    }
    return 0;
}

int AmPlugIn::initLoggingPlugins()
{
    for(auto &plugin : name2logfac) {

        DBG("initialize logging plug-in %s", plugin.first.data());

        int err = plugin.second->onLoad();
        if(err)
            return err;
    }
    return 0;
}

void AmPlugIn::registerLoggingPlugins() {
    // init logging facilities
    for(auto &it : name2logfac) {
        // register for receiving logging messages
        register_log_hook(it.second);
    }
}

int AmPlugIn::loadPlugIn(const string& file, const string& plugin_name)
{
  AmPluginFactory* plugin = NULL; // default: not loaded
  int dlopen_flags = RTLD_NOW;

  char* pname = strdup(plugin_name.c_str());
  char* bname = basename(pname);

  // possibly others
  for (std::set<string>::iterator it=AmConfig.rtld_global_plugins.begin();
       it!=AmConfig.rtld_global_plugins.end();it++) {
    if (!strcmp(bname, it->c_str())) {
      dlopen_flags = RTLD_NOW | RTLD_GLOBAL;
      DBG("using RTLD_NOW | RTLD_GLOBAL to dlopen '%s'", file.c_str());
      break;
    }
  }
  free(pname);

  void* h_dl = dlopen(file.c_str(),dlopen_flags);

  if(!h_dl){
    ERROR("AmPlugIn::loadPlugIn: %s: %s",file.c_str(),dlerror());
    return -1;
  }

  FactoryCreate fc = NULL;
  amci_exports_t* exports = (amci_exports_t*)dlsym(h_dl,"amci_exports");

  bool has_sym=false;
  if(exports){
    if(loadAudioPlugIn(exports))
      goto error;
    goto end;
  }

  if((fc = (FactoryCreate)dlsym(h_dl,FACTORY_SESSION_EXPORT_STR)) != NULL){  
    plugin = (AmPluginFactory*)fc();
    if(loadAppPlugIn(plugin))
      goto error;
    has_sym=true;
  }
  if((fc = (FactoryCreate)dlsym(h_dl,FACTORY_SESSION_EVENT_HANDLER_EXPORT_STR)) != NULL){
    plugin = (AmPluginFactory*)fc();
    if(loadSehPlugIn(plugin))
      goto error;
    has_sym=true;
  }
  if((fc = (FactoryCreate)dlsym(h_dl,FACTORY_PLUGIN_EXPORT_STR)) != NULL){
    plugin = (AmPluginFactory*)fc();
    if(loadBasePlugIn(plugin))
      goto error;
    has_sym=true;
  }
  if((fc = (FactoryCreate)dlsym(h_dl,FACTORY_PLUGIN_CLASS_EXPORT_STR)) != NULL){
    plugin = (AmPluginFactory*)fc();
    if(loadDiPlugIn(plugin))
      goto error;
    has_sym=true;
  }

  if((fc = (FactoryCreate)dlsym(h_dl,FACTORY_PLUGIN_CONF_EXPORT_STR)) != NULL){
    plugin = (AmPluginFactory*)fc();
    if(loadConfPlugIn(plugin))
      goto error;
    has_sym=true;
  }

  if((fc = (FactoryCreate)dlsym(h_dl,FACTORY_LOG_FACILITY_EXPORT_STR)) != NULL){
    plugin = (AmPluginFactory*)fc();
    if(loadLogFacPlugIn(plugin))
      goto error;
    has_sym=true;
  }

  if (NULL != plugin) {
      inc_ref(plugin);
      plugins_objects[plugin_name] = plugin;
  }

  if(!has_sym){
    ERROR("Plugin type could not be detected (%s)(%s)",file.c_str(),dlerror());
    goto error;
  }

 end:
  dlls.push_back(h_dl);
  return 0;

 error:
  dlclose(h_dl);
  return -1;
}


amci_inoutfmt_t* AmPlugIn::fileFormat(const string& fmt_name, const string& ext)
{
  if(!fmt_name.empty()){

    std::map<std::string,amci_inoutfmt_t*>::iterator it = file_formats.find(fmt_name);
    if ((it != file_formats.end()) &&
	(ext.empty() || (ext == it->second->ext)))
      return it->second;
  }
  else if(!ext.empty()){
	
    std::map<std::string,amci_inoutfmt_t*>::iterator it = file_formats.begin();
    for(;it != file_formats.end();++it){
      if(ext == it->second->ext)
	return it->second;
    }
  }

  return 0;
}

amci_codec_t* AmPlugIn::codec(int id)
{
  std::map<int,amci_codec_t*>::const_iterator it = codecs.find(id);
  if(it != codecs.end())
    return it->second;

  return 0;
}

amci_payload_t*  AmPlugIn::payload(int payload_id) const
{
  std::map<int,amci_payload_t*>::const_iterator it = payloads.find(payload_id);
  if(it != payloads.end())
    return it->second;

  return 0;
}

int AmPlugIn::getDynPayload(const string& name, int rate, int encoding_param) const {
  // find a dynamic payload by name/rate and encoding_param (channels, if > 0)
  for(std::map<int, amci_payload_t*>::const_iterator pl_it = payloads.begin();
      pl_it != payloads.end(); ++pl_it)
    if( (!strcasecmp(name.c_str(),pl_it->second->name)
	 && (rate == pl_it->second->advertised_sample_rate)) ) {
      if ((encoding_param > 0) && (pl_it->second->channels > 0) && 
	  (encoding_param != pl_it->second->channels))
	continue;
	  
      return pl_it->first;
    }
  // not found
  return -1;
}

/** return 0, or -1 in case of error. */
void AmPlugIn::getPayloads(vector<SdpPayload>& pl_vec) const
{
  for (std::map<int,int>::const_iterator it = payload_order.begin(); it != payload_order.end(); ++it) {
    std::map<int,amci_payload_t*>::const_iterator pl_it = payloads.find(it->second);
    if(pl_it != payloads.end()){
      // if channels==2 use that value; otherwise don't add channels param
      pl_vec.push_back(SdpPayload(pl_it->first, pl_it->second->name, pl_it->second->advertised_sample_rate, pl_it->second->channels==2?2:0));
    } else {
      ERROR("Payload %d (from the payload_order map) was not found in payloads map!", it->second);
    }
  }
}

amci_subtype_t* AmPlugIn::subtype(amci_inoutfmt_t* iofmt, int subtype)
{
  if(!iofmt)
    return 0;
    
  amci_subtype_t* st = iofmt->subtypes;
  if(subtype<0) // default subtype wanted
    return st;

  for(;;st++){
    if(!st || st->type<0) break;
    if(st->type == subtype)
      return st;
  }

  return 0;
}

amci_subtype_t* AmPlugIn::subtype(amci_inoutfmt_t* iofmt, const string& subtype_name) {
  if(!iofmt)
    return NULL;

  DBG("looking for subtype '%s'", subtype_name.c_str());
  amci_subtype_t* st = iofmt->subtypes;
  if(subtype_name.empty()) // default subtype wanted
    return st;

  for(;;st++){
    if(!st || st->type<0) break;
    if(st->name == subtype_name) {
      return st;
    }
  }
  return NULL;
}

AmSessionFactory* AmPlugIn::getFactory4App(const string& app_name)
{
  AmSessionFactory* res = NULL;

  name2app_mut.lock();
  std::map<std::string,AmSessionFactory*>::iterator it = name2app.find(app_name);
  if(it != name2app.end()) 
    res = it->second;
  name2app_mut.unlock();

  return res;
}

AmSessionEventHandlerFactory* AmPlugIn::getFactory4Seh(const string& name)
{
  std::map<std::string,AmSessionEventHandlerFactory*>::iterator it = name2seh.find(name);
  if(it != name2seh.end())
    return it->second;
  return 0;
}

AmDynInvokeFactory* AmPlugIn::getFactory4Di(const string& name)
{
  std::map<std::string,AmDynInvokeFactory*>::iterator it = name2di.find(name);
  if(it != name2di.end())
    return it->second;
  return 0;
}

void AmPlugIn::listFactories4Di(AmArg &ret)
{
  ret.assertArray();
  for(std::map<string,AmDynInvokeFactory*>::const_iterator it = name2di.begin();
      it != name2di.end(); it++)
  {
    ret.push(it->first);
  }
}

AmConfigFactory* AmPlugIn::getFactory4Config(const string& name)
{
  std::map<std::string,AmConfigFactory*>::iterator it = name2config.find(name);
  if(it != name2config.end())
    return it->second;
  return 0;
}

void AmPlugIn::listFactories4Config(AmArg &ret)
{
  ret.assertArray();
  for(std::map<string,AmConfigFactory*>::const_iterator it = name2config.begin();
      it != name2config.end(); it++)
  {
    ret.push(it->first);
  }
}

AmLoggingFacility* AmPlugIn::getFactory4LogFaclty(const string& name)
{
  std::map<std::string,AmLoggingFacility*>::iterator it = name2logfac.find(name);
  if(it != name2logfac.end())
    return it->second;
  return 0;
}

int AmPlugIn::loadAudioPlugIn(amci_exports_t* exports)
{
  if(!exports){
    ERROR("audio plug-in doesn't contain any exports !");
    return -1;
  }

  if (exports->module_load) {
    if (exports->module_load() < 0) {
      ERROR("initializing audio plug-in!");
      return -1;
    }
  }

  for( amci_codec_t* c=exports->codecs; 
       c->id>=0; c++ ){

    if(addCodec(c))
      goto error;
  }

  for( amci_payload_t* p=exports->payloads; 
       p->name; p++ ){

    if(addPayload(p))
      goto error;
  }

  for(amci_inoutfmt_t* f = exports->file_formats; 
      f->name; f++ ){

    if(addFileFormat(f))
      goto error;
  }
    
  return 0;

 error:
  return -1;
}


int AmPlugIn::loadAppPlugIn(AmPluginFactory* f)
{
  AmSessionFactory* sf = dynamic_cast<AmSessionFactory*>(f);
  if(!sf){
    ERROR("invalid application plug-in!");
    return -1;
  }

  name2app_mut.lock();

  if(name2app.find(sf->getName()) != name2app.end()){
    ERROR("application '%s' already loaded !",sf->getName().c_str());
    name2app_mut.unlock();
    return -1;
  }      

  name2app.insert(std::make_pair(sf->getName(),sf));
  DBG("application '%s' loaded.",sf->getName().c_str());

  inc_ref(sf);
  if(!module_objects.insert(std::make_pair(sf->getName(),sf)).second){
    // insertion failed
    dec_ref(sf);
  }
  name2app_mut.unlock();

  return 0;

}

int AmPlugIn::loadSehPlugIn(AmPluginFactory* f)
{
  AmSessionEventHandlerFactory* sf = dynamic_cast<AmSessionEventHandlerFactory*>(f);
  if(!sf){
    ERROR("invalid session component plug-in!");
    goto error;
  }

  if(name2seh.find(sf->getName()) != name2seh.end()){
    ERROR("session component '%s' already loaded !",sf->getName().c_str());
    goto error;
  }

  inc_ref(sf);
  name2seh.insert(std::make_pair(sf->getName(),sf));
  DBG("session component '%s' loaded.",sf->getName().c_str());

  return 0;

 error:
  return -1;
}

int AmPlugIn::loadBasePlugIn(AmPluginFactory* f)
{
  inc_ref(f);
  if(!name2base.insert(std::make_pair(f->getName(),f)).second){
    // insertion failed
    dec_ref(f);
  }
  return 0;
}

int AmPlugIn::loadDiPlugIn(AmPluginFactory* f)
{
  AmDynInvokeFactory* sf = dynamic_cast<AmDynInvokeFactory*>(f);
  if(!sf){
    ERROR("invalid component plug-in!");
    goto error;
  }

  if(name2di.find(sf->getName()) != name2di.end()){
    ERROR("component '%s' already loaded !",sf->getName().c_str());
    goto error;
  }
  
  name2di.insert(std::make_pair(sf->getName(),sf));
  inc_ref(sf);
  DBG("component '%s' loaded.",sf->getName().c_str());

  return 0;

 error:
  return -1;
}

int AmPlugIn::loadConfPlugIn(AmPluginFactory* f)
{
  std::map<std::string, std::string>::iterator module_it;
  AmConfigFactory* sf = dynamic_cast<AmConfigFactory*>(f);
  if(!sf){
    ERROR("invalid component plug-in %s!", f->getName().c_str());
    goto error;
  }

  module_it = AmConfig.module_config.find(f->getName());
  if(module_it == AmConfig.module_config.end()) {
    ERROR("don't have plug-in %s configuration!", f->getName().c_str());
    goto error;
  }

  if(sf->configure(module_it->second)) {
    ERROR("error in plug-in %s configuration!", f->getName().c_str());
    goto error;
  }
  
  name2config.insert(std::make_pair(sf->getName(),sf));
  inc_ref(sf);

  return 0;
 error:
  return -1;
}

int AmPlugIn::loadLogFacPlugIn(AmPluginFactory* f)
{
  AmLoggingFacility* sf = dynamic_cast<AmLoggingFacility*>(f);
  if(!sf){
    ERROR("invalid logging facility plug-in!");
    goto error;
  }

  if(name2logfac.find(sf->getName()) != name2logfac.end()){
    ERROR("logging facility '%s' already loaded !",
	  sf->getName().c_str());
    goto error;
  }
      
  name2logfac.insert(std::make_pair(sf->getName(),sf));
  inc_ref(sf);
  DBG("logging facility component '%s' loaded.",sf->getName().c_str());

  return 0;

 error:
  return -1;
}

int AmPlugIn::addCodec(amci_codec_t* c)
{
  if(codecs.find(c->id) != codecs.end()){
    ERROR("codec id (%i) already supported",c->id);
    return -1;
  }
  codecs.insert(std::make_pair(c->id,c));
  if(!c->bytes2samples) {
    WARN("codec %i does not provide bytes2samples function",c->id);
  }
  if(!c->samples2bytes) {
    WARN("codec %i does not provide samples2bytes function",c->id);
  }
  DBG("codec id %i inserted",c->id);
  return 0;
}

int AmPlugIn::addPayload(amci_payload_t* p)
{
  if (excluded_payloads.find(p->name) != 
      excluded_payloads.end()) {
    DBG("Not enabling excluded payload '%s'", 
	p->name);
    return 0;
  }

  amci_codec_t* c;
  unsigned int i, id;
  if( !(c = codec(p->codec_id)) ){
    ERROR("in payload '%s': codec id (%i) not supported",
	  p->name, p->codec_id);
    return -1;
  }
  if(p->payload_id != -1){
    if(payloads.find(p->payload_id) != payloads.end()){
      ERROR("payload id (%i) already supported",p->payload_id);
      return -1;
    }
  }
  else {
    p->payload_id = dynamic_pl;
    dynamic_pl++;
  }

  payloads.insert(std::make_pair(p->payload_id,p));
  id = p->payload_id;

  for (i = 0; i < AmConfig.codec_order.size(); i++) {
      if (p->name == AmConfig.codec_order[i]) break;
  }
  if (i >= AmConfig.codec_order.size()) {
      payload_order.insert(std::make_pair(id + 100, id));
      DBG("payload '%s/%i' inserted with id %i and order %i",
	  p->name, p->sample_rate, id, id + 100);
  } else {
      payload_order.insert(std::make_pair(i, id));
      DBG("payload '%s/%i' inserted with id %i and order %i",
	  p->name, p->sample_rate, id, i);
  }

  return 0;
}

int AmPlugIn::addFileFormat(amci_inoutfmt_t* f)
{
  if(file_formats.find(f->name) != file_formats.end()){
    ERROR("file format '%s' already supported",f->name);
    return -1;
  }

  amci_subtype_t* st = f->subtypes;
  for(; st->type >= 0; st++ ){

    if( !codec(st->codec_id) ){
      ERROR("in '%s' subtype %i: codec id (%i) not supported",
	    f->name,st->type,st->codec_id);
      return -1;
    }

    if (st->sample_rate < 0) {
      ERROR("in '%s' subtype %i: rate must be specified!"
	    " (ubr no longer supported)\n", f->name,st->type);
      return -1;
    }
    if (st->channels < 0) {
      ERROR("in '%s' subtype %i: channels must be specified!"
	    "(unspecified channel count no longer supported)\n", f->name,st->type);
      return -1;
    }

  }
  DBG("file format %s inserted",f->name);
  file_formats.insert(std::make_pair(f->name,f));

  return 0;
}

bool AmPlugIn::registerFactory4App(const string& app_name, AmSessionFactory* f)
{
  bool res;

  name2app_mut.lock();
  std::map<std::string,AmSessionFactory*>::iterator it = name2app.find(app_name);
  if(it != name2app.end()){
    WARN("Application '%s' has already been registered and cannot be "
	 "registered a second time\n",
	 app_name.c_str());
    res =  false;
  } else {
    name2app.insert(make_pair(app_name,f));
    res = true;
  }
  name2app_mut.unlock();

  return res;
}

// static alias to registerFactory4App
bool AmPlugIn::registerApplication(const string& app_name, AmSessionFactory* f) {
  bool res = instance()->registerFactory4App(app_name, f);
  if (res) {
    DBG("Application '%s' registered.", app_name.c_str());
  }
  return res;
}

AmSessionFactory* AmPlugIn::findSessionFactory(const AmSipRequest& req, string& app_name)
{
    string m_app_name;

    if(AmConfig.register_application.length() && SIP_METH_REGISTER==req.method)
        m_app_name = AmConfig.register_application;
    else if(AmConfig.options_application.length() && SIP_METH_OPTIONS==req.method)
        m_app_name = AmConfig.options_application;
    else {
        for(const auto &app_selector : AmConfig.applications) {
            switch (app_selector.app_select) {
            case ConfigContainer::App_RURIUSER:
                m_app_name = req.user;
                break;
            case ConfigContainer::App_APPHDR:
                m_app_name = getHeader(req.hdrs, APPNAME_HDR, true);
                break;
            case ConfigContainer::App_RURIPARAM:
                m_app_name = get_header_param(req.r_uri, "app");
                break;
            case ConfigContainer::App_MAPPING:
                m_app_name = ""; // no match if not found
                run_regex_mapping(app_selector.app_mapping, req.r_uri.c_str(), m_app_name);
                break;
            case ConfigContainer::App_SPECIFIED:
                m_app_name = app_selector.application;
                break;
            }
            if(!m_app_name.empty()) break;
        }
    }

    if (m_app_name.empty()) {
      DBG("src_ip: %s callid: %s ruri: %s - "
          "could not find any application matching configured criteria",
          req.remote_ip.c_str(),
          req.callid.c_str(),
          req.r_uri.c_str());
      return NULL;
    }
    
    AmSessionFactory* session_factory = getFactory4App(m_app_name);
    if(!session_factory) {
      ERROR("AmPlugIn::findSessionFactory: application '%s' not found !", m_app_name.c_str());
    }
    
    app_name = m_app_name;
    return session_factory;
}

void AmPlugIn::dumpPlugins(std::map<string, string>& ret)
{
    std::for_each(plugins_objects.begin(), plugins_objects.end(), [&ret](const std::pair<string, AmPluginFactory*>& pf)
                  {
                      ret[pf.second->getName()] = pf.second->getVersion();
                  });
}

#define REGISTER_STUFF(comp_name, map_name, param_name)			\
  if(instance()->map_name.find(param_name) != instance()->map_name.end()){	\
  ERROR(comp_name "'%s' already registered !", param_name.c_str());	\
  return false;								\
  }									\
  inc_ref(f);								\
  instance()->map_name.insert(std::make_pair(param_name,f));		\
  DBG(comp_name " '%s' registered.",param_name.c_str());		\
  return true;

bool AmPlugIn::registerSIPEventHandler(const string& seh_name,
				       AmSessionEventHandlerFactory* f) {
  REGISTER_STUFF("SIP Event handler", name2seh, seh_name);
}

bool AmPlugIn::registerDIInterface(const string& di_name, AmDynInvokeFactory* f) {
  REGISTER_STUFF("DI Interface", name2di, di_name);
}

bool AmPlugIn::registerLoggingFacility(const string& lf_name, AmLoggingFacility* f) {
  REGISTER_STUFF("Logging Facility", name2logfac, lf_name);
}

#undef REGISTER_STUFF

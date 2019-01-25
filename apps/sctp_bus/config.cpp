#include "config.h"

cfg_reader::cfg_reader(const string& mod_name)
  : cfg(nullptr), mod_name(mod_name)
{}

cfg_reader::~cfg_reader()
{
  if(cfg) cfg_free(cfg);
}

#define LOG_BUF_SIZE 2048
void cfg_reader_error(cfg_t *cfg, const char *fmt, va_list ap)
{
    int l = 0;
    char buf[LOG_BUF_SIZE];
    if(cfg->title) {
    //if(cfg->opts->flags & CFGF_TITLE) {
        l = snprintf(buf,LOG_BUF_SIZE,"line:%d section '%s'(%s): ",
            cfg->line,
            cfg->name,
            cfg->title);
    } else {
        l = snprintf(buf,LOG_BUF_SIZE,"line:%d section '%s': ",
            cfg->line,
            cfg->name);
    }
    l+= vsnprintf(buf+l,LOG_BUF_SIZE-l,fmt,ap);
    ERROR("%.*s",l,buf);
}

bool cfg_reader::read(const string &config, cfg_opt_t *opts)
{
    cfg =  cfg_init(opts, CFGF_NONE);
    if(!cfg) return false;

    cfg_set_error_function(cfg,cfg_reader_error);

    switch(cfg_parse_buf(cfg, config.c_str())) {
    case CFG_SUCCESS:
        break;
    case CFG_PARSE_ERROR:
        ERROR("configuration of module %s parse error",mod_name.c_str());
        return false;
    default:
        ERROR("unexpected error on configuration of module %s processing",mod_name.c_str());
        return false;
    }
    return true;
}

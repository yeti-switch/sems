#include "config.h"

cfg_reader::cfg_reader()
  : cfg(nullptr)
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

bool cfg_reader::read(const string &path, cfg_opt_t *opts)
{
    cfg =  cfg_init(opts, CFGF_NONE);
    if(!cfg) return false;

    cfg_set_error_function(cfg,cfg_reader_error);

    switch(cfg_parse(cfg, path.c_str())) {
    case CFG_SUCCESS:
        break;
    case CFG_FILE_ERROR:
        DBG("configuration file: %s could not be read: %s",path.c_str(),strerror(errno));
        return true;
    case CFG_PARSE_ERROR:
        ERROR("configuration file %s parse error",path.c_str());
        return false;
    default:
        ERROR("unexpected error on configuration file %s processing",path.c_str());
        return false;
    }
    return true;
}

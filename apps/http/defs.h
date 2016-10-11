#pragma once

//#define ENABLE_DEBUG 1

#ifdef ENABLE_DEBUG
    #define CDBG(fmt, args...)  DBG(fmt, ##args)
#else
    #define CDBG(fmt, args...) ;
#endif

#define EPOLL_MAX_EVENTS    2048

#define easy_setopt(opt,val) \
    if(CURLE_OK!=curl_easy_setopt(curl,opt,val)){ \
        ERROR("curl_easy_setopt error for option" #opt); \
        return -1; \
    }

#define multi_setopt(opt,val)\
    if(CURLE_OK!=curl_multi_setopt(curl_multi,opt,val)){ \
        ERROR("curl_multi_setopt error for option" #opt); \
        return -1; \
    }

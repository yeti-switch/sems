/*
 * Copyright (C) 2002-2003 Fhg Fokus
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

#pragma once

#include <sys/types.h>	/* pid_t */
#include <stdio.h>
#include <unistd.h>	/* getpid() */
#include <pthread.h>	/* pthread_self() */
#include <execinfo.h>   /* backtrace_symbols() */
#include <cxxabi.h> /* __cxa_demangle() */
#include <string>

#include "atomic_types.h"

extern __thread pthread_t _self_tid;
extern __thread pid_t     _self_pid;

/**
 * @{ Log levels
 */
enum Log_Level {
  L_ERR = 0,
  L_WARN,
  L_INFO,
  L_DBG
};
/** @} */

#define FIX_LOG_LEVEL(level) \
  ((level) < L_ERR ? L_ERR : ((level) > L_DBG ? L_DBG : (level)))

#ifndef __FILENAME__
#define __FILENAME__ __FILE__
#endif

#ifdef __cplusplus
# ifdef PRETTY_FUNCTION_LOG
#  define FUNC_NAME __PRETTY_FUNCTION__
# else
#  define FUNC_NAME __FUNCTION__
#endif
#else
# define FUNC_NAME __FUNCTION__
#endif

#ifdef __linux
# ifndef _GNU_SOURCE
#  define _GNU_SOURCE
# endif
# include <linux/unistd.h>
# include <sys/syscall.h>
# define GET_PID() syscall(SYS_getpid)
#else
# define GET_PID() getpid()
#endif

#ifdef _DEBUG
# ifndef NO_THREADID_LOG
#  define GET_TID() pthread_self()
#  define LOC_FMT   " [#%lx/%u] [%s, %s:%d]"
#  define LOC_DATA  (unsigned long)tid, pid, func, file, line
# else
#  define GET_TID() 0
#  define LOC_FMT   " [%u] [%s %s:%d]"
#  define LOC_DATA  pid, func, file, line
# endif
#else
# define GET_TID() syscall(SYS_gettid)
# define LOC_FMT   " [%u/%u] [%s:%d] "
# define LOC_DATA  pid, tid, file, line
#endif

#ifdef LOG_LOC_DATA_ATEND
#define COMPLETE_LOG_FMT "%s: %s" LOC_FMT "\n", log_level2str[level_], msg_, LOC_DATA
#else
#define COMPLETE_LOG_FMT LOC_FMT " %s: %.*s" "\n", LOC_DATA, log_level2str[level_], msg_len_, msg_
#endif

#ifndef LOG_BUFFER_LEN
#define LOG_BUFFER_LEN 4096
#endif

extern int log_level;
extern __thread char log_buf[LOG_BUFFER_LEN];

void run_log_hooks(int level, pid_t pid, pthread_t tid,
                   const char* func, const char* file, int line,
                   const char* msg, int msg_len);

class ContextLoggingHook
  : public atomic_ref_cnt
{
  public:
    virtual ~ContextLoggingHook() {}
    virtual void log(int level, const char* msg, int msg_len) = 0;
};

template<class... Types> void write_log(
    int level, const char* func, const char* file, int line,
    ContextLoggingHook *context_logger,
    const char *fmt, Types... args)
{
    //level = FIX_LOG_LEVEL(level);
    if(level > log_level && !context_logger) return;

    if constexpr (sizeof...(args) > 0) {
        int n = snprintf(log_buf, sizeof(log_buf), fmt, args...);
        if(n > LOG_BUFFER_LEN) n = LOG_BUFFER_LEN;
        if(log_buf[n-1] == '\n') n--;

        run_log_hooks(level, _self_pid, _self_tid,
                      func, file, line, log_buf, n);
        if(context_logger) context_logger->log(level, log_buf, n);
    } else {
        int n = std::char_traits<char>::length(fmt);
        if(fmt[n-1] == '\n') n--;

        run_log_hooks(level, _self_pid, _self_tid,
                      func, file, line, fmt, n);
        if(context_logger) context_logger->log(level, fmt, n);
    }
}

#define _LOG(level__, fmt, args...) \
    write_log(level__, FUNC_NAME, __FILE__, __LINE__, nullptr, fmt, ##args)

#define _LOG_CTX(context_logger, level__, fmt, args...) \
    write_log(level__, FUNC_NAME, __FILE__, __LINE__, context_logger, fmt, ##args)

/**
 * @{ Logging macros
 */

#define CAT_ERROR(error_category, fmt, args... ) \
  _LOG(L_ERR, error_category fmt, ##args)
#define CAT_WARN(error_category, fmt, args... ) \
_LOG(L_WARN, error_category fmt, ##args)
#define CAT_INFO(error_category, fmt, args... ) \
  _LOG(L_INFO, error_category fmt, ##args)
#define CAT_DBG(error_category, fmt, args... ) \
  _LOG(L_DBG, error_category fmt, ##args)

#define CAT_ERROR_CTX(context_logger, error_category, fmt, args... ) \
  _LOG_CTX(context_logger, L_ERR, error_category fmt, ##args)
#define CAT_WARN_CTX(context_logger, error_category, fmt, args... ) \
  _LOG_CTX(context_logger, L_WARN, error_category fmt, ##args)
#define CAT_INFO_CTX(context_logger, error_category, fmt, args... ) \
  _LOG_CTX(context_logger, L_INFO, error_category fmt, ##args)
#define CAT_DBG_CTX(context_logger, error_category, fmt, args... ) \
  _LOG_CTX(context_logger, L_DBG, error_category fmt, ##args)

#define CATEGORIZED_PREFIX    "SNMP:"
#define CATEGORY_ERROR      CATEGORIZED_PREFIX "0"
#define CATEGORY_WARNING    CATEGORIZED_PREFIX "1"
#define CATEGORY_INFO       CATEGORIZED_PREFIX "2"
#define CATEGORY_DEBUG      CATEGORIZED_PREFIX "3"

#ifdef USE_LOG_CATEGORY_PREFIXES
# define ERROR_CATEGORY_EGENERAL CATEGORY_ERROR   ".0" " "
# define ERROR_CATEGORY_WGENERAL CATEGORY_WARNING ".0" " "
# define ERROR_CATEGORY_IGENERAL CATEGORY_INFO    ".0" " "
# define ERROR_CATEGORY_DGENERAL CATEGORY_DEBUG   ".0" " "
#else
# define ERROR_CATEGORY_EGENERAL
# define ERROR_CATEGORY_WGENERAL
# define ERROR_CATEGORY_IGENERAL
# define ERROR_CATEGORY_DGENERAL
#endif

#define ERROR(fmt, args...) CAT_ERROR(ERROR_CATEGORY_EGENERAL, fmt, ##args)
#define WARN(fmt, args...)  CAT_WARN(ERROR_CATEGORY_WGENERAL, fmt, ##args)
#define INFO(fmt, args...)  CAT_INFO(ERROR_CATEGORY_IGENERAL, fmt, ##args)
#define DBG(fmt, args...)   CAT_DBG(ERROR_CATEGORY_DGENERAL, fmt, ##args)

#define ERROR_CTX(context_logger, fmt, args...) CAT_ERROR_CTX(context_logger, ERROR_CATEGORY_EGENERAL, fmt, ##args)
#define WARN_CTX(context_logger, fmt, args...)  CAT_WARN_CTX(context_logger, ERROR_CATEGORY_WGENERAL, fmt, ##args)
#define INFO_CTX(context_logger, fmt, args...)  CAT_INFO_CTX(context_logger, ERROR_CATEGORY_IGENERAL, fmt, ##args)
#define DBG_CTX(context_logger, fmt, args...)   CAT_DBG_CTX(context_logger, ERROR_CATEGORY_DGENERAL, fmt, ##args)

#define CLASS_LOG_FMT "[%p] "
#define CLASS_ARGS static_cast<void *>(this)
#define CLASS_ERROR(fmt, args...) ERROR(CLASS_LOG_FMT fmt, CLASS_ARGS, ##args)
#define CLASS_WARN(fmt, args...)  WARN(CLASS_LOG_FMT fmt, CLASS_ARGS, ##args)
#define CLASS_INFO(fmt, args...)  INFO(CLASS_LOG_FMT fmt, CLASS_ARGS, ##args)
#define CLASS_DBG(fmt, args...)   DBG(CLASS_LOG_FMT fmt, CLASS_ARGS, ##args)

#define CLASS_ERROR_CTX(context_logger, fmt, args...) ERROR_CTX(context_logger, CLASS_LOG_FMT fmt, CLASS_ARGS, ##args)
#define CLASS_WARN_CTX(context_logger, fmt, args...)  WARN_CTX(context_logger, CLASS_LOG_FMT fmt, CLASS_ARGS, ##args)
#define CLASS_INFO_CTX(context_logger, fmt, args...)  INFO_CTX(context_logger, CLASS_LOG_FMT fmt, CLASS_ARGS, ##args)
#define CLASS_DBG_CTX(context_logger, fmt, args...)   DBG_CTX(context_logger, CLASS_LOG_FMT fmt, CLASS_ARGS, ##args)

//#define SOCKET_LOG(fmt, args...) INFO(fmt, ##args)
#define SOCKET_LOG(fmt, args...) ;

#define to_void(var) static_cast<void *>(var)

/** @} */

extern const char* log_level2str[];

void init_logging(const char* name);
void cleanup_logging();

#ifndef DISABLE_SYSLOG_LOG
int set_syslog_facility(const char*, const char* );
#endif

void log_stacktrace(int ll);

#define log_demangled_stacktrace __lds
void __lds(int ll, unsigned int max_frames = 63);

class AmLoggingFacility;
void register_log_hook(AmLoggingFacility*);
//void unregister_log_hook(AmLoggingFacility*);

bool get_higher_levels(int& log_level_arg);

void set_log_level(int log_level_arg);
void register_stderr_facility();
void set_stderr_log_level(int log_level_arg);

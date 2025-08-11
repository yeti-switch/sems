/*
 * $Id: parse_common.h 1486 2009-08-29 14:40:38Z rco $
 *
 * Copyright (C) 2007 Raphael Coeffic
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

#ifndef _parse_common_h
#define _parse_common_h

#include "cstring.h"

#include <list>
using std::list;

//
// Constants
//

#define UNDEFINED_ERR      -1
#define UNEXPECTED_EOT     -2
#define UNEXPECTED_EOL     -3
#define MALFORMED_SIP_MSG  -4
#define INCOMPLETE_SIP_MSG -5
#define MALFORMED_URI      -6
#define MALFORMED_FLINE    -7

#define IS_IN(c, l, r) (((c) >= (l)) && ((c) <= (r)))

#define CR        (0x0d) // '\r'
#define LF        (0x0a) // '\n'
#define SP        (0x20) // ' '
#define HTAB      (0x09) // '\t'
#define IS_WSP(c) (SP == (c) || HTAB == (c))

#define HCOLON    (':')
#define SEMICOLON (';')
#define COMMA     (',')
#define DQUOTE    ('"')
#define SLASH     ('/')
#define BACKSLASH ('\\')
#define HYPHEN    ('-')

#define IS_ALPHA(c)    (IS_IN(c, 0x41, 0x5a) || IS_IN(c, 0x61, 0x7a))
#define IS_DIGIT(c)    IS_IN(c, 0x30, 0x39)
#define IS_ALPHANUM(c) (IS_ALPHA(c) || IS_DIGIT(c))

// #define IS_UPPER(c) IS_IN(c,0x41,0x5a)
// #define LOWER_B(c) (IS_UPPER(c) ? ((c)+0x20) : (c))
#define IS_UPPER(c) (c & 0x20 == 0)
#define LOWER_B(c)  (c | 0x20)

// TODO: wouldn't a switch work quicker?
#define IS_TOKEN(c)                                                                                                    \
    (IS_ALPHANUM(c) || ((c) == '-') || ((c) == '.') || ((c) == '!') || ((c) == '%') || ((c) == '*') || ((c) == '_') || \
     ((c) == '+') || ((c) == '`') || ((c) == '\'') || ((c) == '~'))

#define IS_MARK(c)                                                                                                     \
    (((c) == '-') || ((c) == '_') || ((c) == '.') || ((c) == '!') || ((c) == '~') || ((c) == '*') || ((c) == '\'') ||  \
     ((c) == '(') || ((c) == ')'))

#define IS_UNRESERVED(c) (IS_ALPHANUM(c) || IS_MARK(c))

#define IS_USER_UNRESERVED(c)                                                                                          \
    (((c) == '&') || ((c) == '=') || ((c) == '+') || ((c) == '$') || ((c) == ',') || ((c) == ';') || ((c) == '?') ||   \
     ((c) == '/'))

#define IS_USER(c) (IS_UNRESERVED(c) || IS_USER_UNRESERVED(c)) // Escaped chars missing

//
// SIP version constants
//

#define SIP_str    "SIP"
#define SUP_SIPVER "2.0"

#define HTTP_str "HTTP"

#define SIP_len        (sizeof(SIP_str) - /*0-term*/ 1)
#define SUP_SIPVER_len (sizeof(SUP_SIPVER) - /*0-term*/ 1)

#define HTTP_len (sizeof(HTTP_str) - /*0-term*/ 1)

#define SIPVER_len (SIP_len + 1 + SUP_SIPVER_len) // 'SIP/2.0'

#define HTTPVER_len (HTTP_len + 1 + SUP_SIPVER_len) // 'HTTP/2.0' fixme

//
// SIP headers max values
//

#define GEN_MAX_NUM_str "4294967295" // (pow(2, 32) - 1)
#define GEN_MAX_NUM_len (sizeof(GEN_MAX_NUM_str) - /*0-term*/ 1)

#define CSEQ_MAX_NUM_str            GEN_MAX_NUM_str
#define CSEQ_MAX_NUM_len            GEN_MAX_NUM_len
#define MAX_FRW_MAX_NUM             255
#define EXPIRES_MAX_NUM_str         GEN_MAX_NUM_str
#define EXPIRES_MAX_NUM_len         GEN_MAX_NUM_len
#define CONTACT_EXPIRES_MAX_NUM_str GEN_MAX_NUM_str
#define CONTACT_EXPIRES_MAX_NUM_len GEN_MAX_NUM_len

//
// SIP headers default values
//

#define EXPIRES_DEFAULT_NUM_str "3600"
#define EXPIRES_DEFAULT_NUM_len (sizeof(EXPIRES_DEFAULT_NUM_str) - /*0-term*/ 1)

//
// Common states: (>100)
//

enum { ST_CR = 100, ST_LF, ST_CRLF };

#define case_CR_LF                                                                                                     \
    case CR:                                                                                                           \
        saved_st = st;                                                                                                 \
        st       = ST_CR;                                                                                              \
        break;                                                                                                         \
    case LF:                                                                                                           \
        saved_st = st;                                                                                                 \
        st       = ST_LF;                                                                                              \
        break

#define case_ST_CR(c)                                                                                                  \
    case ST_CR:                                                                                                        \
        if ((c) == LF) {                                                                                               \
            st = ST_CRLF;                                                                                              \
        } else {                                                                                                       \
            DBG("CR without LF");                                                                                      \
            return MALFORMED_SIP_MSG;                                                                                  \
        }                                                                                                              \
        break

//
// Structs
//

struct sip_avp {
    cstring name;
    cstring value;

    sip_avp()
        : name()
        , value()
    {
    }

    sip_avp(const cstring &n, const cstring &v)
        : name(n)
        , value(v)
    {
    }
};


//
// Functions
//

inline int lower_cmp(const char *l, const char *r, int len)
{
    const char *end = l + len;

    while (l != end) {
        if (LOWER_B(*l) == LOWER_B(*r)) {
            l++;
            r++;
            continue;
        } else if (LOWER_B(*l) < LOWER_B(*r)) {
            return -1;
        } else {
            return 1;
        }
        l++;
        r++;
    }

    return 0;
}

inline int lower_cmp_n(const char *l, int llen, const char *r, int rlen)
{
    if (llen == rlen)
        return lower_cmp(l, r, rlen);
    else if (llen < rlen)
        return -1;

    return 1;
}

inline int lower_cmp_n(const cstring &l, const cstring &r)
{
    return lower_cmp_n(l.s, l.len, r.s, r.len);
}

int parse_sip_version(const char *beg, int len);

/**
 * Parse a list of Attribute-Value pairs beginning with
 * and separated by semi-colons until stop_char or the
 * end of the string is reached.
 */
int parse_gen_params_sc(list<sip_avp *> *params, const char **c, int len, char stop_char);

/**
 * Parse a list of Attribute-Value pairs separated
 * by semi-colons until stop_char or the end of
 * the string is reached.
 */
int parse_gen_params(list<sip_avp *> *params, const char **c, int len, char stop_char);

/** Free the parameters in the list (NOT the list itself) */
void free_gen_params(list<sip_avp *> *params);

#endif

/** EMACS **
 * Local variables:
 * mode: c++
 * c-basic-offset: 4
 * End:
 */

/*
 * $Id: parse_uri.cpp 1714 2010-03-30 14:47:36Z rco $
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


#include "parse_common.h"
#include "parse_uri.h"
#include "log.h"

sip_uri::sip_uri()
    : scheme(UNKNOWN)
    , port(0)
    , trsp(nullptr)
{
}

sip_uri::~sip_uri()
{
    list<sip_avp *>::iterator it;

    for (it = params.begin(); it != params.end(); ++it) {
        delete *it;
    }

    for (it = hdrs.begin(); it != hdrs.end(); ++it) {
        delete *it;
    }

    for (it = uri_params.begin(); it != uri_params.end(); ++it) {
        delete *it;
    }
}


static int parse_sip_uri(sip_uri *uri, const char *beg, int len, bool no_default_port)
{
    enum { URI_USER = 0, URI_PW, URI_HOST, URI_HOST_V6, URI_PORT, URI_PNAME, URI_PVALUE, URI_HNAME, URI_HVALUE };

    int         st = URI_HOST;
    const char *c  = beg;
    // int escaped = 0;

    cstring tmp1, tmp2;

    // Search for '@', so that we can decide
    // wether to start in URI_USER or URI_HOST state.
    // This is not very efficient, but it makes the
    // parser much easier!

    for (; c != beg + len; c++) {
        // user part present in URI
        if (*c == '@') {
            st = URI_USER;
            break;
        }
    }

    if (st == URI_USER) {
        uri->user.s = beg;
    } else {
        uri->host.s = beg;
    }

    c = beg;

    for (; c != beg + len; c++) {
        switch (*c) {
        case HCOLON:
            switch (st) {
            case URI_USER:
                uri->user.len = c - uri->user.s;
                if (!uri->user.len) {
                    DBG("Password given for empty user!");
                    return MALFORMED_URI;
                }
                uri->passwd.s = c + 1;
                st            = URI_PW;
                break;
            case URI_HOST:
                uri->host.len = c - uri->host.s;
                if (!uri->host.len) {
                    DBG("Empty host part");
                    return MALFORMED_URI;
                }
                uri->port_str.s = c + 1;
                st              = URI_PORT;
                break;
            } // switch(st)
            break;
        case '@':
            switch (st) {
            case URI_USER:
                uri->user.len = c - uri->user.s;
                st            = URI_HOST;
                uri->host.set(c + 1, 0);
                break;
            case URI_PW:
                uri->passwd.len = c - uri->passwd.s;
                st              = URI_HOST;
                uri->host.set(c + 1, 0);
                break;
            default:
                DBG("Illegal char '@' in non-user part");
                return MALFORMED_URI;
                break;
            } // switch(st)
            break;
        case ';':
            switch (st) {
            case URI_HOST:
                uri->host.len = c - uri->host.s;
                st            = URI_PNAME;
                tmp1.set(c + 1, 0);
                break;
            case URI_PORT:
                uri->port_str.len = c - uri->port_str.s;
                st                = URI_PNAME;
                tmp1.set(c + 1, 0);
                break;
            case URI_HNAME:
                tmp1.len = c - tmp1.s;
                uri->hdrs.push_back(new sip_avp(tmp1, cstring(0, 0)));
                st = URI_PNAME;
                tmp1.set(c + 1, 0);
                break;
            case URI_PNAME:
                // DBG("Empty URI parameter");
                // return MALFORMED_URI;
                tmp1.len = c - tmp1.s;
                uri->params.push_back(new sip_avp(tmp1, cstring(0, 0)));
                tmp1.s = c + 1;
                break;
            case URI_PVALUE:
                tmp2.len = c - tmp2.s;
                uri->params.push_back(new sip_avp(tmp1, tmp2));
                // DBG("uri param: \"%.*s\"=\"%.*s\"",
                //     tmp1.len, tmp1.s,
                //     tmp2.len, tmp2.s);
                tmp1.s = c + 1;
                st     = URI_PNAME;
                break;
            } // switch(st)
            break;
        case '?':
            switch (st) {
            case URI_HOST:
                uri->host.len = c - uri->host.s;
                st            = URI_HNAME;
                tmp1.s        = c + 1;
                break;
            case URI_PORT:
                uri->port_str.len = c - uri->port_str.s;
                st                = URI_HNAME;
                tmp1.s            = c + 1;
                break;
            case URI_PNAME:
                // DBG("Empty URI parameter");
                // return MALFORMED_URI;
                tmp1.len = c - tmp1.s;
                uri->params.push_back(new sip_avp(tmp1, cstring(0, 0)));
                tmp1.s = c + 1;
                st     = URI_HNAME;
                break;
            case URI_PVALUE:
                tmp2.len = c - tmp2.s;
                uri->params.push_back(new sip_avp(tmp1, tmp2));
                // DBG("uri param: \"%.*s\"=\"%.*s\"",
                //     tmp1.len, tmp1.s,
                //     tmp2.len, tmp2.s);
                tmp1.s = c + 1;
                st     = URI_HNAME;
                break;
            } // switch(st)
            break;
        case '=':
            switch (st) {
            case URI_PNAME:
            case URI_HNAME:
                tmp1.len = c - tmp1.s;
                if (!tmp1.len) {
                    DBG("Empty param/header name");
                    return MALFORMED_URI;
                }
                tmp2.s = c + 1;
                st++;
                break;
            }
            break;
        case '&':
            switch (st) {
            case URI_HNAME: DBG("Empty URI header"); return MALFORMED_URI;
            case URI_HVALUE:
                tmp2.len = c - tmp2.s;
                uri->hdrs.push_back(new sip_avp(tmp1, tmp2));
                // DBG("uri hdr: \"%.*s\"=\"%.*s\"",
                //     tmp1.len, tmp1.s,
                //     tmp2.len, tmp2.s);
                tmp1.s = c + 1;
                st     = URI_HNAME;
                break;
            }
            break;
        case '[':
            switch (st) {
            case URI_HOST: st = URI_HOST_V6; break;
            }
            break;
        case ']':
            switch (st) {
            case URI_HOST_V6: st = URI_HOST; break;
            }
            break;
        } // switch(*c)
    } // for(;c!=beg+len;c++)

    switch (st) {
    case URI_USER:
    case URI_PW:   DBG("Missing host part"); return MALFORMED_URI;
    case URI_HOST:
        uri->host.len = c - uri->host.s;
        if (!uri->host.len) {
            DBG("Missing host part");
            return MALFORMED_URI;
        }
        break;
    case URI_PORT: uri->port_str.len = c - uri->port_str.s; break;
    case URI_PNAME:
        // DBG("Empty URI parameter");
        // return MALFORMED_URI;
        tmp1.len = c - tmp1.s;
        uri->params.push_back(new sip_avp(tmp1, cstring(0, 0)));
        break;
    case URI_PVALUE:
        tmp2.len = c - tmp2.s;
        uri->params.push_back(new sip_avp(tmp1, tmp2));
        // DBG("uri param: \"%.*s\"=\"%.*s\"",
        //     tmp1.len, tmp1.s,
        //     tmp2.len, tmp2.s);
        break;
    case URI_HNAME: DBG("Empty URI header"); return MALFORMED_URI;
    case URI_HVALUE:
        tmp2.len = c - tmp2.s;
        uri->hdrs.push_back(new sip_avp(tmp1, tmp2));
        // DBG("uri hdr: \"%.*s\"=\"%.*s\"",
        //     tmp1.len, tmp1.s,
        //     tmp2.len, tmp2.s);
        break;
    } // switch(st)

    if (uri->port_str.len) {
        uri->port = 0;
        for (unsigned int i = 0; i < uri->port_str.len; i++) {
            uri->port = uri->port * 10 + (uri->port_str.s[i] - '0');
        }
    } else if (!no_default_port) {
        uri->port = 5060;
    }

    /*DBG("Converted URI port (%.*s) to int (%i)",
        uri->port_str.len,uri->port_str.s,uri->port);*/

    for (list<sip_avp *>::iterator it = uri->params.begin(); it != uri->params.end(); it++) {
        if (!lower_cmp_n((*it)->name.s, (*it)->name.len, "transport", 9)) {
            uri->trsp = *it;
        }
    }

    return 0;
}

static int parse_tel_uri(sip_uri *uri, const char *beg, int len)
{
    // https://www.rfc-editor.org/rfc/rfc3966#section-3
    enum { TEL_NUMBER = 0, TEL_PNAME, TEL_PVALUE } st = TEL_NUMBER;

    cstring     tmp1, tmp2;
    const char *c = beg;

    uri->user.s = beg;

    for (; c != beg + len; c++) {
        switch (*c) {
        case SEMICOLON:
            switch (st) {
            case TEL_NUMBER:
                uri->user.len = c - uri->user.s;
                if (!uri->user.len) {
                    DBG("empty number");
                    return MALFORMED_URI;
                }
                st = TEL_PNAME;
                tmp1.set(c + 1, 0);
                break;
            case TEL_PNAME:
                tmp1.len = c - tmp1.s;
                uri->params.push_back(new sip_avp(tmp1, cstring(0, 0)));
                tmp1.s = c + 1;
                break;
            case TEL_PVALUE:
                tmp2.len = c - tmp2.s;
                uri->params.push_back(new sip_avp(tmp1, tmp2));
                tmp1.s = c + 1;
                st     = TEL_PNAME;
                break;
            }
            break;
        case '=':
            switch (st) {
            case TEL_NUMBER: DBG("not allowed symbol"); return MALFORMED_URI;
            case TEL_PNAME:
                tmp1.len = c - tmp1.s;
                if (!tmp1.len) {
                    DBG("empty header name");
                    return MALFORMED_URI;
                }
                tmp2.s = c + 1;
                st     = TEL_PVALUE;
                break;
            case TEL_PVALUE: break;
            }
            break;
            /*
            //global-number-digits = "+" *phonedigit DIGIT *phonedigit
            case '+':
                if(st==TEL_NUMBER && c!=beg) {
                    DBG("'+' is allowed at the number start only");
                    return MALFORMED_URI;
                }
                break;
            //phonedigit = DIGIT / [ visual-separator ]
            //visual-separator = "-" / "." / "(" / ")"
            case '0'...'9':
            case '-':
            case '.':
            case '(':
            case ')':
                break;
            default:
                if(st==TEL_NUMBER) {
                    DBG("not allowed symbol '%c' in the tel number",
                        *c);
                    return MALFORMED_URI;
                }
                break;
            */
        }
    }

    switch (st) {
    case TEL_NUMBER:
        uri->user.len = c - uri->user.s;
        if (!uri->user.len) {
            DBG("empty number");
            return MALFORMED_URI;
        }
        break;
    case TEL_PNAME:
        tmp1.len = c - tmp1.s;
        uri->params.push_back(new sip_avp(tmp1, cstring(0, 0)));
        break;
    case TEL_PVALUE:
        tmp2.len = c - tmp2.s;
        uri->params.push_back(new sip_avp(tmp1, tmp2));
        break;
    }

    return 0;
}

int parse_nameaddr(sip_uri *uri, const char *beg, int len, bool no_default_port)
{
    enum {
        NAMEADDR_BEG = 0,
        NAMEAADDR,
        URI,
        PARAMS,
        PNAME,
        PVALUE,
    };

    int         st      = NAMEADDR_BEG;
    const char *c       = beg;
    const char *uri_str = 0;
    char        quote   = ' ';

    cstring tmp1, tmp2;

    for (; c != beg + len; c++) {
        switch (st) {
        case NAMEADDR_BEG:
            switch (*c) {
            case 's':
            case 'S': return parse_uri(uri, beg, len, no_default_port);
            case ' ': break;
            case '\"':
            case '\'':
                quote            = *c;
                st               = NAMEAADDR;
                uri->name_addr.s = c + 1;
                break;
            case '<':
                uri_str = c + 1;
                st      = URI;
                break;
            }
        default:
            st               = NAMEAADDR;
            uri->name_addr.s = c;
            break;
        case NAMEAADDR:
            if (*c == quote) {
                st                 = URI;
                uri->name_addr.len = c - uri->name_addr.s;
            }
            break;
        case URI:
            if (*c == '<') {
                uri_str = c + 1;
            }
            if (*c == '>') {
                if (parse_uri(uri, uri_str, c - uri_str, no_default_port)) {
                    return MALFORMED_URI;
                }
                st = PARAMS;
            }
            break;
        case PARAMS:
            if (*c == ';') {
                tmp1.set(c + 1, 0);
                st = PNAME;
            }
            break;
        case PNAME:
            if (*c == ';') {
                if (c - tmp1.s) {
                    tmp1.len = c - tmp1.s;
                    uri->uri_params.push_back(new sip_avp(tmp1, { 0, 0 }));
                }
                tmp1.set(c + 1, 0);
            } else if (*c == '=') {
                tmp1.len = c - tmp1.s;
                tmp2.set(c + 1, 0);
                st = PVALUE;
            }
            break;
        case PVALUE:
            if (*c == ';') {
                tmp2.len = c - tmp2.s;
                uri->uri_params.push_back(new sip_avp(tmp1, tmp2));
                st = PNAME;
            }
            break;
        }
    }

    switch (st) {
    case PNAME:
        tmp1.len = beg + len - tmp1.s;
        uri->uri_params.push_back(new sip_avp(tmp1, { 0, 0 }));
        break;
    case PVALUE:
        tmp2.len = beg + len - tmp2.s;
        uri->uri_params.push_back(new sip_avp(tmp1, tmp2));
        break;
    }

    return 0;
}

int parse_uri(sip_uri *uri, const char *beg, int len, bool no_default_port)
{
    enum {
        URI_BEG = 0,
        SIP_S,  // Sip
        SIP_I,  // sIp
        SIP_P,  // siP
        SIPS_S, // sipS
        TEL_T,  // Tel
        TEL_E,  // tEl
        TEL_L   // teL
    };

    int         st = URI_BEG;
    const char *c  = beg;

    for (; c != beg + len; c++) {
        switch (st) {
        case URI_BEG:
            switch (*c) {
            case 's':
            case 'S': st = SIP_S; continue;
            case 't':
            case 'T': st = TEL_T; continue;
            default:  DBG("Unknown URI scheme"); return MALFORMED_URI;
            }
            break;
        case SIP_S:
            switch (*c) {
            case 'i':
            case 'I': st = SIP_I; continue;
            default:  DBG("Unknown URI scheme"); return MALFORMED_URI;
            }
            break;
        case SIP_I:
            switch (*c) {
            case 'p':
            case 'P': st = SIP_P; continue;
            default:  DBG("Unknown URI scheme"); return MALFORMED_URI;
            }
            break;
        case SIP_P:
            switch (*c) {
            case HCOLON:
                // DBG("scheme: sip");
                uri->scheme = sip_uri::SIP;
                return parse_sip_uri(uri, c + 1, len - (c + 1 - beg), no_default_port);
            case 's':
            case 'S': st = SIPS_S; continue;
            default:  DBG("Unknown URI scheme"); return MALFORMED_URI;
            }
            break;
        case SIPS_S:
            switch (*c) {
            case HCOLON:
                // DBG("scheme: sips");
                uri->scheme = sip_uri::SIPS;
                return parse_sip_uri(uri, c + 1, len - (c + 1 - beg), no_default_port);
            default: DBG("Unknown URI scheme"); return MALFORMED_URI;
            }
            break;
        case TEL_T:
            switch (*c) {
            case 'e':
            case 'E': st = TEL_E; continue;
            default:  DBG("Unknown URI scheme"); return MALFORMED_URI;
            }
            break;
        case TEL_E:
            switch (*c) {
            case 'l':
            case 'L': st = TEL_L; continue;
            default:  DBG("Unknown URI scheme"); return MALFORMED_URI;
            }
            break;
        case TEL_L:
            switch (*c) {
            case HCOLON:
                // DBG("scheme: sips");
                uri->scheme = sip_uri::TEL;
                return parse_tel_uri(uri, c + 1, len - (c + 1 - beg));
            default: DBG("Unknown URI scheme"); return MALFORMED_URI;
            }
        default: DBG("bug: unknown state"); return UNDEFINED_ERR;
        } // switch(st)
    } // for(;c!=beg+len;c++)

    return 0;
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-basic-offset: 4
 * End:
 */

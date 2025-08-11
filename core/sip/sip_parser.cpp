/*
 * $Id: sip_parser.cpp 1486 2009-08-29 14:40:38Z rco $
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


#include "sip_parser.h"
#include "parse_header.h"
#include "parse_common.h"
#include "parse_via.h"
#include "parse_cseq.h"
#include "parse_from_to.h"
#include "parse_100rel.h"
#include "transport.h"
#include "log.h"
#include "../AmUtils.h"
#include "defs.h"

#include <memory>
using std::unique_ptr;

sip_msg::sip_msg(const char *msg_buf, int msg_len)
    : buf(NULL)
    , type(SIP_UNKNOWN)
    , hdrs()
    , to(NULL)
    , from(NULL)
    , cseq(NULL)
    , rack(NULL)
    , via1(NULL)
    , via_p1(NULL)
    , callid(NULL)
    , max_forwards(NULL)
    , expires(NULL)
    , contacts()
    , route()
    , record_route()
    , content_type(NULL)
    , content_length(NULL)
    , body()
    , connection(NULL)
    , upgrade(NULL)
    , origin(NULL)
    , sec_ws_version(NULL)
    , sec_ws_key(NULL)
    , sec_ws_ext(NULL)
    , sec_ws_accept(NULL)
    , sec_ws_protocol(NULL)
    , local_socket(NULL)
{
    u.request = 0;
    u.reply   = 0;

    copy_msg_buf(msg_buf, msg_len);

    memset(&local_ip, 0, sizeof(sockaddr_storage));
    memset(&remote_ip, 0, sizeof(sockaddr_storage));
}

sip_msg::sip_msg()
    : buf(NULL)
    , len(0)
    , type(SIP_UNKNOWN)
    , hdrs()
    , to(NULL)
    , from(NULL)
    , cseq(NULL)
    , rack(NULL)
    , via1(NULL)
    , via_p1(NULL)
    , callid(NULL)
    , max_forwards(NULL)
    , expires(NULL)
    , contacts()
    , route()
    , record_route()
    , content_type(NULL)
    , content_length(NULL)
    , body()
    , connection(NULL)
    , upgrade(NULL)
    , origin(NULL)
    , sec_ws_version(NULL)
    , sec_ws_key(NULL)
    , sec_ws_ext(NULL)
    , sec_ws_accept(NULL)
    , sec_ws_protocol(NULL)
    , local_socket(NULL)
    , transport_id(sip_transport::UNPARSED)
{
    u.request = 0;
    u.reply   = 0;

    memset(&local_ip, 0, sizeof(sockaddr_storage));
    memset(&remote_ip, 0, sizeof(sockaddr_storage));
}

sip_msg::~sip_msg()
{
    delete[] buf;

    list<sip_header *>::iterator it;
    for (it = hdrs.begin(); it != hdrs.end(); ++it) {
        delete *it;
    }

    if (u.request) {
        if ((type == SIP_REQUEST || type == HTTP_REQUEST) && u.request) {
            delete u.request;
        } else if ((type == SIP_REPLY || type == HTTP_REPLY) && u.reply) {
            delete u.reply;
        }
    }

    if (local_socket)
        dec_ref(local_socket);
}

void sip_msg::copy_msg_buf(const char *msg_buf, int msg_len)
{
    buf = new char[msg_len + 1];
    memcpy(buf, msg_buf, msg_len);
    buf[msg_len] = '\0';
    len          = msg_len;
}

void sip_msg::release()
{
    buf = NULL;
    hdrs.clear();
    u.request = NULL;
    if (local_socket)
        dec_ref(local_socket);
    local_socket = NULL;
}

int sip_msg::send(unsigned int flags)
{
    assert(local_socket);
    return local_socket->send(&remote_ip, buf, len, flags);
}


const char *INVITEm = "INVITE";
#define INVITE_len 6

const char *ACKm = "ACK";
#define ACK_len 3

const char *OPTIONSm = "OPTIONS";
#define OPTIONS_len 7

const char *BYEm = "BYE";
#define BYE_len 3

const char *CANCELm = "CANCEL";
#define CANCEL_len 6

const char *REGISTERm = "REGISTER";
#define REGISTER_len 8

const char *PRACKm = "PRACK";
#define PRACK_len 5

const char *GETm = "GET";
#define GET_len 3

int parse_method(int *method, const char *beg, int len)
{
    const char *c   = beg;
    const char *end = c + len;

    *method = sip_request::OTHER_METHOD;

    switch (len) {
    case INVITE_len:
        // case CANCEL_len:
        switch (*c) {
        case 'I':
            if (!memcmp(c + 1, INVITEm + 1, INVITE_len - 1))
                *method = sip_request::INVITE;
            break;
        case 'C':
            if (!memcmp(c + 1, CANCELm + 1, CANCEL_len - 1))
                *method = sip_request::CANCEL;
            break;
        }
        break;

    case ACK_len:
        // case BYE_len:
        switch (*c) {
        case 'A':
            if (!memcmp(c + 1, ACKm + 1, ACK_len - 1))
                *method = sip_request::ACK;
            break;
        case 'B':
            if (!memcmp(c + 1, BYEm + 1, BYE_len - 1))
                *method = sip_request::BYE;
            break;
        case 'G':
            if (!memcmp(c + 1, GETm + 1, GET_len - 1))
                *method = sip_request::GET;
            break;
        }
    case OPTIONS_len:
        if (!memcmp(c + 1, OPTIONSm + 1, OPTIONS_len - 1))
            *method = sip_request::OPTIONS;
        break;

    case REGISTER_len:
        if (!memcmp(c + 1, REGISTERm + 1, REGISTER_len - 1))
            *method = sip_request::REGISTER;
        break;

    case PRACK_len:
        if (!memcmp(c, PRACKm, PRACK_len))
            *method = sip_request::PRACK;
        break;
    } // switch(len)

    // other method
    for (; c != end; c++) {
        if (!IS_TOKEN(*c)) {
            DBG("!IS_TOKEN(%c): MALFORMED_SIP_MSG", *c);
            return MALFORMED_SIP_MSG;
        }
    }

    if (*method == sip_request::OTHER_METHOD) {
        // DBG("Found other method (%.*s)",len,beg);
    }

    return 0;
}


static int parse_first_line(sip_msg *msg, char **c, char *end)
{
    enum {
        FL_METH = 0,
        FL_RURI,

        FL_SIPVER1, //'S' || 'H'

        FL_SIPVER2, // 'I'
        FL_SIPVER3, // 'P'

        FL_SIPVER4, // 'T'
        FL_SIPVER5, // 'T'
        FL_SIPVER6, // 'P'

        FL_SIPVER7, // '/'

        FL_SIPVER_DIG1_1, // 1st digit for sip '2'
        FL_SIPVER_DIG1_2, // 1st digit for http '0' || '1'
        FL_SIPVER_SEP_1,  // '.' for sip
        FL_SIPVER_SEP_2,  // '.' for http 0.9
        FL_SIPVER_SEP_3,  // '.' for http 1.1 || 1.0
        FL_SIPVER_DIG2_1, // 2st digit for sip '0'
        FL_SIPVER_DIG2_2, // 2st digit for http 0.9
        FL_SIPVER_DIG2_3, // 2st digit for http 1.0 || 1.1

        FL_SIPVER_SP, // ' '

        FL_STAT1,
        FL_STAT2,
        FL_STAT3,
        FL_STAT_SP,
        FL_REASON,

        FL_EOL,
        FL_ERR
    };

    char *beg      = *c;
    int   saved_st = 0, st = FL_SIPVER1;
    int   err = 0;

    bool is_request = false;

    for (; (*c < end) && **c; (*c)++) {
        switch (st) {

#define case_SIPVER_case1(ch1, st2)                                                                                    \
    case ch1: st = st2;

#define case_SIPVER_case2(ch1, ch2, st2)                                                                               \
    case ch1:                                                                                                          \
    case ch2: st = st2;

#define case_SIPVER_case3(ch1, ch2, ch3, st2)                                                                          \
    case ch1:                                                                                                          \
    case ch2:                                                                                                          \
    case ch3: st = st2;

#define case_SIPVER_type(type1, type2)                                                                                 \
    if (is_request)                                                                                                    \
        msg->type = type1;                                                                                             \
    else                                                                                                               \
        msg->type = type2;                                                                                             \
    break;

#define case_SIPVER_BEGIN(st1)                                                                                         \
    case st1:                                                                                                          \
        switch (**c) {

#define case_SIPVER_END()                                                                                              \
    default:                                                                                                           \
        if (!is_request) {                                                                                             \
            st = FL_METH;                                                                                              \
            (*c)--;                                                                                                    \
        } else {                                                                                                       \
            st = FL_ERR;                                                                                               \
        }                                                                                                              \
        }                                                                                                              \
        break;

#define case_SIPVER(ch1, ch2, st1, st2)                                                                                \
    case_SIPVER_BEGIN(st1) case_SIPVER_case2(ch1, ch2, st2) break;                                                     \
    case_SIPVER_END()

            case_SIPVER_BEGIN(FL_SIPVER1) case_SIPVER_case2('S', 's', FL_SIPVER2)
                case_SIPVER_type(SIP_REQUEST, SIP_REPLY) case_SIPVER_case2('H', 'h', FL_SIPVER4)
                    case_SIPVER_type(HTTP_REQUEST, HTTP_REPLY) case_SIPVER_END()

                        case_SIPVER('I', 'i', FL_SIPVER2, FL_SIPVER3);
            case_SIPVER('P', 'p', FL_SIPVER3, FL_SIPVER7);

            case_SIPVER('T', 't', FL_SIPVER4, FL_SIPVER5);
            case_SIPVER('T', 't', FL_SIPVER5, FL_SIPVER6);
            case_SIPVER('P', 'p', FL_SIPVER6, FL_SIPVER7);

        case FL_SIPVER7: // '/'
            if (**c == '/') {
                if (msg->type <= SIP_REPLY)
                    st = FL_SIPVER_DIG1_1;
                else if (msg->type <= HTTP_REPLY)
                    st = FL_SIPVER_DIG1_2;
            } else if (!is_request) {
                st = FL_METH;
                (*c)--;
            } else {
                st = FL_ERR;
            }
            break;

#undef case_SIPVER
#undef case_SIPVER_END
#define case_SIPVER_END()                                                                                              \
    default: st = FL_ERR; break;                                                                                       \
        }                                                                                                              \
        break;

#define case_SIPVER(ch1, st1, st2)                                                                                     \
    case_SIPVER_BEGIN(st1) case_SIPVER_case1(ch1, st2) break;                                                          \
    case_SIPVER_END()

            case_SIPVER('2', FL_SIPVER_DIG1_1, FL_SIPVER_SEP_1) case_SIPVER_BEGIN(FL_SIPVER_DIG1_2)
                case_SIPVER_case1('0', FL_SIPVER_SEP_2) break;
            case_SIPVER_case1('1', FL_SIPVER_SEP_3) break;
            case_SIPVER_END() case_SIPVER('.', FL_SIPVER_SEP_1, FL_SIPVER_DIG2_1)
                case_SIPVER('.', FL_SIPVER_SEP_2, FL_SIPVER_DIG2_2) case_SIPVER('.', FL_SIPVER_SEP_3, FL_SIPVER_DIG2_3)
                    case_SIPVER_BEGIN(FL_SIPVER_DIG2_1) case_SIPVER_case1('0', FL_SIPVER_SP) if (is_request) st =
                        FL_EOL;
            else msg->u.reply = new sip_reply;
            break;
            case_SIPVER_END() case_SIPVER_BEGIN(FL_SIPVER_DIG2_2) case_SIPVER_case1('9', FL_SIPVER_SP) if (is_request)
                st            = FL_EOL;
            else msg->u.reply = new sip_reply;
            break;
            case_SIPVER_END() case_SIPVER_BEGIN(FL_SIPVER_DIG2_3)
                case_SIPVER_case2('0', '1', FL_SIPVER_SP) if (is_request) st = FL_EOL;
            else msg->u.reply                                                = new sip_reply;
            break;
        case_SIPVER_END()

            case FL_METH:
            switch (**c) {
            case SP:
                msg->u.request = new sip_request;
                msg->u.request->method_str.set(beg, *c - beg);
                err = parse_method(&msg->u.request->method, beg, *c - beg);
                if (err)
                    return err;
                st  = FL_RURI;
                beg = *c + 1;
                break;

                //      default:
                //          if (!IS_TOKEN(**c)) {
                //              DBG("Bad char in request method: 0x%.2x",**c);
                //              return MALFORMED_SIP_MSG;
                //          }
                //      break;
            }
            break;

        case FL_RURI:
            switch (**c) {
            case SP:
                msg->u.request->ruri_str.set(beg, *c - beg);
                if (msg->u.request->method <= sip_request::REGISTER) {
                    err = parse_uri(&msg->u.request->ruri, beg, *c - beg);
                    if (err)
                        return err;
                }
                st         = FL_SIPVER1;
                is_request = true;
                break;
            case CR:
            case LF:
            case HTAB: DBG("Bad char in request URI: 0x%x", **c); return MALFORMED_SIP_MSG;
            }
            break;

        case FL_SIPVER_SP:
            if (**c != SP)
                st = FL_ERR;
            else {
                st  = FL_STAT1;
                beg = *c + 1;
            }
            break;

#define case_STCODE(st1)                                                                                               \
    case st1:                                                                                                          \
        if (IS_DIGIT(**c)) {                                                                                           \
            st++;                                                                                                      \
            msg->u.reply->code *= 10;                                                                                  \
            msg->u.reply->code += **c - '0';                                                                           \
        } else {                                                                                                       \
            st = FL_ERR;                                                                                               \
        }                                                                                                              \
        break

            case_STCODE(FL_STAT1);
            case_STCODE(FL_STAT2);
            case_STCODE(FL_STAT3);

#undef case_STCODE

        case FL_STAT_SP:
            if (**c != SP)
                st = FL_ERR;
            else {
                st  = FL_REASON;
                beg = *c + 1;
            }
            break;

        case FL_REASON:
            switch (**c) {
                case_CR_LF;
            }
            break;

        case FL_EOL:
            switch (**c) {
                case_CR_LF;
            default: DBG("Bad char at the end of first line: 0x%x", **c); return MALFORMED_SIP_MSG;
            }
            break;

        case FL_ERR: return MALFORMED_SIP_MSG; case_ST_CR(**c);

        case ST_LF:
        case ST_CRLF:
            if (saved_st == FL_REASON) {
                if (int reason_len = *c - (st == ST_CRLF ? 2 : 1) - beg; reason_len != 0) {
                    msg->u.reply->reason.set(beg, reason_len);
                }
            }
            return 0;

        default: DBG("Bad state! st=%i", st); return -99;
        } // switch(st)
    } // for(;(*c < end) && **c;(*c)++)

    return UNEXPECTED_EOT;
}

int parse_headers(sip_msg *msg, char **c, char *end, const char *&err_msg)
{
    list<sip_header *> hdrs;
    int                err = parse_headers(hdrs, c, end);
    if (!err) {
        for (auto hdr : hdrs) {
            switch (hdr->type) {

            case sip_header::H_CALL_ID:
                if (msg->callid) {
                    err     = MALFORMED_SIP_MSG;
                    err_msg = "duplicated Call-ID header";
                }
                msg->callid = hdr;
                break;

            case sip_header::H_MAX_FORWARDS:
                if (msg->max_forwards) {
                    err     = MALFORMED_SIP_MSG;
                    err_msg = "duplicated Max-Forwards header";
                }
                msg->max_forwards = hdr;
                break;

            case sip_header::H_CONTACT: msg->contacts.push_back(hdr); break;

            case sip_header::H_CONTENT_LENGTH:
                if (msg->content_length) {
                    err     = MALFORMED_SIP_MSG;
                    err_msg = "duplicated Content-Length header";
                }
                msg->content_length = hdr;
                break;

            case sip_header::H_CONTENT_TYPE: msg->content_type = hdr; break;

            case sip_header::H_FROM:
                if (msg->from) {
                    err     = MALFORMED_SIP_MSG;
                    err_msg = "duplicated From header";
                }
                msg->from = hdr;
                break;

            case sip_header::H_TO:
                if (msg->to) {
                    err     = MALFORMED_SIP_MSG;
                    err_msg = "duplicated To header";
                }
                msg->to = hdr;
                break;

            case sip_header::H_VIA:
                if (!msg->via1)
                    msg->via1 = hdr;
                msg->vias.push_back(hdr);
                break;

                // case sip_header::H_RSEQ:
                // 	msg->rseq = hdr;
                // 	break;

            case sip_header::H_RACK:
                if (msg->type == SIP_REQUEST && msg->u.request->method == sip_request::PRACK) {
                    msg->rack = hdr;
                }
                break;

            case sip_header::H_CSEQ:
                if (msg->cseq) {
                    err     = MALFORMED_SIP_MSG;
                    err_msg = "duplicated CSeq header";
                }
                msg->cseq = hdr;
                break;

            case sip_header::H_ROUTE:           msg->route.push_back(hdr); break;

            case sip_header::H_RECORD_ROUTE:    msg->record_route.push_back(hdr); break;

            case sip_header::H_CONNECTION:      msg->connection = hdr; break;

            case sip_header::H_UPGRADE:         msg->upgrade = hdr; break;

            case sip_header::H_ORIGIN:          msg->origin = hdr; break;

            case sip_header::H_SEC_WS_VERSION:  msg->sec_ws_version = hdr; break;

            case sip_header::H_SEC_WS_KEY:      msg->sec_ws_key = hdr; break;

            case sip_header::H_SEC_WS_EXT:      msg->sec_ws_ext = hdr; break;

            case sip_header::H_SEC_WS_PROTOCOL: msg->sec_ws_protocol = hdr; break;

            case sip_header::H_SEC_WS_ACCEPT:   msg->sec_ws_accept = hdr; break;

            case sip_header::H_EXPIRES:         msg->expires = hdr; break;
            } // switch(hdr->type)

            msg->hdrs.push_back(hdr);
            if (err)
                break;
        } // for(auto hdr: hdrs)
    }

    return err;
}

int parse_sip_msg(sip_msg *msg, const char *&err_msg)
{
    char *c   = msg->buf;
    char *end = msg->buf + msg->len;
    int   num;

    int err = parse_first_line(msg, &c, end);

    if (err) {
        err_msg = "Could not parse first line";
        return MALFORMED_FLINE;
    }

    err = parse_headers(msg, &c, end, err_msg);
    /*for(const auto &h: msg->hdrs) {
        DBG("h: type:%d, name:'%.*s', value:'%.*s'",
            h->type,
            h->name.len, h->name.s,
            h->value.len, h->value.s);
    }*/
    if (err)
        return err;

    msg->body.set(c, msg->len - (c - msg->buf));

    if (msg->type > SIP_REPLY) {
        err_msg = "incorrect type of protocol";
        return MALFORMED_SIP_MSG;
    }

    if (msg->type == SIP_REQUEST && msg->u.request->method > sip_request::REGISTER) {
        err_msg = "incorrect method of protocol";
        return MALFORMED_SIP_MSG;
    }

    if (!msg->via1 || !msg->cseq || !msg->from || !msg->to || !msg->callid) {
        if (!msg->via1) {
            err_msg = "missing Via header field";
        } else if (!msg->cseq) {
            err_msg = "missing CSeq header field";
        } else if (!msg->from) {
            err_msg = "missing From header field";
        } else if (!msg->to) {
            err_msg = "missing To header field";
        } else if (!msg->callid) {
            err_msg = "missing Call-ID header field";
        }

        return INCOMPLETE_SIP_MSG;
    }

    unique_ptr<sip_via> via(new sip_via());
    if (!parse_via(via.get(), msg->via1->value.s, msg->via1->value.len) && !via->parms.empty()) {
        msg->via_p1  = *via->parms.begin();
        msg->via1->p = via.release();
    } else {
        err_msg = "could not parse Via hf";
        return MALFORMED_SIP_MSG;
    }

    unique_ptr<sip_cseq> cseq(new sip_cseq());
    if (!parse_cseq(cseq.get(), msg->cseq->value.s, msg->cseq->value.len) && cseq->num_str.len && cseq->method_str.len)
    {
        msg->cseq->p = cseq.release();
    } else {
        err_msg = "could not parse CSeq hf";
        return MALFORMED_SIP_MSG;
    }

    unique_ptr<sip_from_to> from(new sip_from_to());
    if (parse_from_to(from.get(), msg->from->value.s, msg->from->value.len) != 0) {
        err_msg = "could not parse From hf";
        return MALFORMED_SIP_MSG;
    }
    if (!from->tag.len) {
        err_msg = "missing From-tag";
        return MALFORMED_SIP_MSG;
    }
    msg->from->p = from.release();

    unique_ptr<sip_from_to> to(new sip_from_to());
    if (!parse_from_to(to.get(), msg->to->value.s, msg->to->value.len)) {
        msg->to->p = to.release();
    } else {
        err_msg = "could not parse To hf";
        return MALFORMED_SIP_MSG;
    }

    if (msg->rack) {
        unique_ptr<sip_rack> rack(new sip_rack());
        if (parse_rack(rack.get(), msg->rack->value.s, msg->rack->value.len)) {
            msg->rack->p = rack.release();
        } else {
            err_msg = "could not parse RAck hf";
            return MALFORMED_SIP_MSG;
        }
    }

    if (msg->content_length && msg->content_length->value.isEmpty() == false &&
        str2int(msg->content_length->value.s, msg->content_length->value.len, num) &&
        (num < 0 || (num > 0 && static_cast<unsigned int>(num) > msg->body.len + 2))) // + 2 (CR+LF)
    {
        return MALFORMED_SIP_MSG;
    }

    if (msg->max_forwards && msg->max_forwards->value.isEmpty() == false &&
        str2int(msg->max_forwards->value.s, msg->max_forwards->value.len, num) && num > MAX_FRW_MAX_NUM)
    {
        DBG("\"%s\" header value is greater than %d", SIP_HDR_MAX_FORWARDS, MAX_FRW_MAX_NUM);
        /* exclude Max-Forwards from headers list */
        // msg->hdrs.remove(msg->max_forwards);
        // delete msg->max_forwards;
        // msg->max_forwards = NULL;
    }

    if (msg->expires && msg->expires->value.isEmpty() == false &&
        strncmp2(msg->expires->value.s, msg->expires->value.len, EXPIRES_MAX_NUM_str, EXPIRES_MAX_NUM_len) > 0)
    {
        DBG("\"%s\" header value is greater than %s", SIP_HDR_EXPIRES, EXPIRES_MAX_NUM_str);
        /* use default value for Expires header */
        // msg->expires->value.set(EXPIRES_DEFAULT_NUM_str, EXPIRES_DEFAULT_NUM_len);
    }

    if (msg->type == SIP_REQUEST && msg->u.request && msg->cseq && msg->cseq->p) {
        sip_cseq    *cseq = (sip_cseq *)msg->cseq->p;
        sip_request *req  = msg->u.request;

        if (cseq->method != req->method ||
            strncmp2(cseq->method_str.s, cseq->method_str.len, req->method_str.s, req->method_str.len) != 0)
        {
            DBG("\"%s\" method %.*s mismatched for the %.*s method in the start line", SIP_HDR_CSEQ,
                cseq->method_str.len, cseq->method_str.s, req->method_str.len, req->method_str.s);

            return MALFORMED_SIP_MSG;
        }
    }

    return 0;
}

int parse_http_msg(sip_msg *msg, const char *&err_msg)
{
    char *c   = msg->buf;
    char *end = msg->buf + msg->len;

    int err = parse_first_line(msg, &c, end);

    if (err) {
        err_msg = "Could not parse first line";
        return MALFORMED_FLINE;
    }

    err = parse_headers(msg, &c, end, err_msg);

    if (!err) {
        msg->body.set(c, msg->len - (c - msg->buf));
    }

    if (msg->type < HTTP_REQUEST) {
        err_msg = "incorrect type of protocol";
        return MALFORMED_SIP_MSG;
    }

    if (msg->type == HTTP_REQUEST && msg->u.request->method < sip_request::GET) {
        err_msg = "incorrect method of protocol";
        return MALFORMED_SIP_MSG;
    }

    if (!msg->connection || !msg->upgrade || !msg->sec_ws_version) {
        if (!msg->connection) {
            err_msg = "missing Connection header field";
        } else if (!msg->upgrade) {
            err_msg = "missing upgrade header field";
        } else if (!msg->sec_ws_version) {
            err_msg = "missing sec_websocket_version header field";
        }

        return INCOMPLETE_SIP_MSG;
    }

    if (msg->type == HTTP_REQUEST && !msg->sec_ws_key) {
        err_msg = "missing sec_websocket_key header field";
        return INCOMPLETE_SIP_MSG;
    }

    if (msg->type == HTTP_REPLY && !msg->sec_ws_accept) {
        err_msg = "missing sec_websocket_accept header field";
        return INCOMPLETE_SIP_MSG;
    }

    return 0;
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-basic-offset: 4
 * End:
 */

/*
 * $Id: sip_parser.h 1486 2009-08-29 14:40:38Z rco $
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
 * For a license to use the sems software under conditions
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

#include "cstring.h"
#include "parse_uri.h"

#include <netinet/in.h>
#include <sys/socket.h>

struct sip_request;
struct sip_reply;
struct sip_header;
struct sip_via_parm;
struct dns_handle;
class trsp_socket;

//
// SIP message types:
//

enum {
    SIP_UNKNOWN=0,
    SIP_REQUEST,
    SIP_REPLY,
    HTTP_REQUEST,
    HTTP_REPLY
};


struct sip_request
{
    enum {
        OTHER_METHOD=0,
        //sip method
        INVITE,
        ACK,
        PRACK,
        OPTIONS,
        BYE,
        CANCEL,
        REGISTER,
        //http method
        GET
    };

    //
    // Request methods
    //
    cstring  method_str;
    int      method;

    cstring  ruri_str;
    sip_uri  ruri;
};

struct sip_reply
{
    int     code;
    cstring reason;
    bool local_reply;

    sip_reply()
      : code(0),
        local_reply(false)
    {}

    sip_reply(int code, const cstring& reason)
      : code(code), reason(reason),
        local_reply(false)
    {}
};

struct sip_msg
{
    char*   buf;
    int     len;

    // Request or Reply?
    int     type; 

    union {
        struct sip_request* request;
        struct sip_reply*   reply;
    } u;

    std::list<sip_header*>  hdrs;

    sip_header*        to;
    sip_header*        from;

    sip_header*        cseq;
    sip_header*        rack;

    std::list<sip_header*>  vias;
    sip_header*        via1;
    sip_via_parm*      via_p1;

    sip_header*        callid;
    sip_header*        max_forwards;
    sip_header*        expires;

    std::list<sip_header*>  contacts;
    std::list<sip_header*>  route;
    std::list<sip_header*>  record_route;
    sip_header*        content_type;
    sip_header*        content_length;
    cstring            body;

    sip_header*        connection;
    sip_header*        upgrade;
    sip_header*        origin;
    sip_header*        sec_ws_version;
    sip_header*        sec_ws_key;
    sip_header*        sec_ws_ext;
    sip_header*        sec_ws_accept;
    sip_header*        sec_ws_protocol;

    sockaddr_storage   local_ip;
    trsp_socket*       local_socket;

    sockaddr_storage   remote_ip;

    timeval recv_timestamp;
    unsigned int transport_id;

    sip_msg();
    sip_msg(const char* msg_buf, int msg_len);
    ~sip_msg();

    void copy_msg_buf(const char* msg_buf, int msg_len);

    int send(unsigned flags);

    /**
     * Releases pointers otherwise deleted by the destructor
     * This is useful to abandon the memory pointed at if this
     * message is a copy of another which do own the memory.
     */
    void release();
};

int parse_method(int* method, const char* beg, int len);
int parse_headers(sip_msg* msg, char** c, char* end);
int parse_sip_msg(sip_msg* msg, char*& err_msg);
int parse_http_msg(sip_msg* msg, char*& err_msg);

#define get_contact(msg) (msg->contacts.empty() ? NULL : (*msg->contacts.begin()))

/** EMACS **
 * Local variables:
 * mode: c++
 * c-basic-offset: 4
 * End:
 */

/*
 * $Id: parse_from_to.h 850 2008-04-04 21:29:36Z sayer $
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

#ifndef _parse_from_to_h
#define _parse_from_to_h

#include "sip_parser.h"
#include "parse_header.h"
#include "parse_nameaddr.h"

struct sip_from_to : public sip_parsed_hdr {
    sip_nameaddr nameaddr;
    cstring      tag;

    sip_from_to()
        : sip_parsed_hdr()
    {
    }
    ~sip_from_to() {}
};

int parse_from_to(sip_from_to *ft, const char *beg, int len);

inline sip_from_to *get_from(const sip_msg *msg)
{
    return dynamic_cast<sip_from_to *>(msg->from->p);
}

inline sip_from_to *get_to(const sip_msg *msg)
{
    return dynamic_cast<sip_from_to *>(msg->to->p);
}

#endif

/** EMACS **
 * Local variables:
 * mode: c++
 * c-basic-offset: 4
 * End:
 */

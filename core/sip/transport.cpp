/*
 * $Id: transport.cpp 1048 2008-07-15 18:48:07Z sayer $
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
#include "transport.h"
#include "../log.h"
#include "sip/ip_util.h"

#include "parse_via.h"

#include <assert.h>
#include <netinet/in.h>
#include <string.h> // memset, strerror, ...
#include <AmLcConfig.h>

int trsp_socket::log_level_raw_msgs = L_DBG;

const char *trsp_socket::socket_transport2proto_str(const socket_transport transport)
{
    switch (transport & sock_transport_proto_mask) {
    case tr_proto_udp: return "udp";
    case tr_proto_tcp: return "tcp";
    case tr_proto_tls: return "tls";
    case tr_proto_ws:  return "ws";
    case tr_proto_wss: return "wss";
    default:           return "invalid";
    }
}

trsp_socket::trsp_socket(unsigned short if_num_, unsigned short proto_idx_, unsigned int opts, socket_transport trans,
                         unsigned int sys_if_idx_, int sd_)
    : sd(sd_)
    , client(sd == -1 ? true : false)
    , ip()
    , port(0)
    , actual_ip()
    , actual_port(0)
    , if_num(if_num_)
    , proto_idx(proto_idx_)
    , sys_if_idx(sys_if_idx_)
    , socket_options(opts)
    , transport(trans)
    , tos_byte(0)
{
    memset(&addr, 0, sizeof(sockaddr_storage));
    time_created = time(0);
}

trsp_socket::~trsp_socket() {}

int trsp_socket::set_tos_byte(uint8_t byte)
{
    DBG("trying to set IP_TOS for %d socket buffer to 0x%02x", sd, byte);

    int tos = byte;

    int ret = setsockopt(sd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    if (ret < 0) {
        ERROR("failed to set IP_TOS 0x%0x for socket %d. err: %d", byte, sd, ret);
        return 1;
    }

    int       set_tos;
    socklen_t toslen = sizeof(tos);
    ret              = getsockopt(sd, IPPROTO_IP, IP_TOS, &set_tos, &toslen);
    if (ret < 0) {
        ERROR("failed to get IP_TOS for socket %d. err: %d", sd, ret);
        return 1;
    }

    if (set_tos != tos) {
        ERROR("failed to set IP_TOS for %d", sd);
        return 1;
    }

    tos_byte = byte;

    return 0;
}

int trsp_socket::get_transport_proto_id() const
{
    // TODO: use bitmask here as for PI_interface::local_ip_proto2addr_if
    switch (transport) {
    case udp_ipv4:
    case udp_ipv6: return sip_transport::UDP;
    case tcp_ipv4:
    case tcp_ipv6: return sip_transport::TCP;
    case tls_ipv4:
    case tls_ipv6: return sip_transport::TLS;
    case ws_ipv4:
    case ws_ipv6:  return sip_transport::WS;
    case wss_ipv4:
    case wss_ipv6: return sip_transport::WSS;
    default:       ERROR("unexpected transport: %d. set UNPARSED as fallback", transport); return sip_transport::UNPARSED;
    }
}

const char *trsp_socket::get_ip() const
{
    return ip.c_str();
}

unsigned short trsp_socket::get_port() const
{
    return port;
}

const string &trsp_socket::get_actual_ip() const
{
    return actual_ip;
}

unsigned short trsp_socket::get_actual_port() const
{
    return actual_port;
}

unsigned int trsp_socket::get_options() const
{
    return socket_options;
}

void trsp_socket::set_public_ip(const string &ip)
{
    public_ip = ip;
}

void trsp_socket::set_public_domain(const string &domain)
{
    public_domain = domain;
}

void trsp_socket::set_announce_port(bool announce)
{
    announce_port = announce;
}

bool trsp_socket::get_announce_port() const
{
    return announce_port;
}

const char *trsp_socket::get_advertised_host() const
{
    if (!public_domain.empty())
        return public_domain.data();

    if (!public_ip.empty())
        return public_ip.c_str();

    return get_ip();
}

bool trsp_socket::is_opt_set(unsigned int mask) const
{
    // DBG("trsp_socket::socket_options = 0x%x",socket_options);
    return (socket_options & mask) == mask;
}

void trsp_socket::copy_addr_to(sockaddr_storage *sa) const
{
    memcpy(sa, &addr, sizeof(sockaddr_storage));
}

/**
 * Match with the given address
 * @return true if address matches
 */
bool trsp_socket::match_addr(sockaddr_storage *other_addr) const
{

    if (addr.ss_family != other_addr->ss_family)
        return false;

    if (addr.ss_family == AF_INET) {
        return SAv4(&addr)->sin_addr.s_addr == SAv4(other_addr)->sin_addr.s_addr;
    } else if (addr.ss_family == AF_INET6) {
        return IN6_ARE_ADDR_EQUAL(&(SAv6(&addr))->sin6_addr, &(SAv6(other_addr))->sin6_addr);
    }

    return false;
}

int trsp_socket::get_sd() const
{
    return sd;
}

unsigned short trsp_socket::get_if() const
{
    return if_num;
}

unsigned short trsp_socket::get_proto_idx() const
{
    return proto_idx;
}

trsp_acl::action_t trsp_acl::check(const sockaddr_storage &ip) const
{
    if (networks.empty())
        return Allow;

    for (vector<AmSubnet>::const_iterator i = networks.begin(); i != networks.end(); ++i) {
        if (i->contains(ip))
            return Allow;
    }
    return action;
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-basic-offset: 4
 * End:
 */

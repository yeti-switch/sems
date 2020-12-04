/*
 * $Id: transport.h 1048 2008-07-15 18:48:07Z sayer $
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
#ifndef _transport_h_
#define _transport_h_

#include "../AmThread.h"
#include "../atomic_types.h"
#include "../AmSubnet.h"
#include <sys/socket.h>
#include "AmArg.h"

#include <string>
using std::string;

#include <vector>
using std::vector;

#define DEFAULT_IDLE_TIMEOUT 3600000 /* 1 hour */
#define DEFAULT_TCP_CONNECT_TIMEOUT 2000 /* 2 seconds */

#define sock_transport_addr_shift(v) (v << 3)
#define sock_transport_addr_mask  0x8
#define sock_transport_proto_mask 0x7

class trsp_socket
    : public atomic_ref_cnt
{
public:
    enum socket_options {
        force_via_address       = (1 << 0),
        force_outbound_if       = (1 << 1),
        use_raw_sockets         = (1 << 2),
        no_transport_in_contact = (1 << 3),
        static_client_port = (1 << 4)
    };

    //3 low bits of socket_transport
    enum socket_transport_proto {
        tr_proto_invalid  = 0,
        tr_proto_udp,
        tr_proto_tcp,
        tr_proto_tls,
        tr_proto_ws,
        tr_proto_wss
    };

    //4th bit of socket_transport
    enum socket_transport_addr_family {
        tr_addr_family_ipv4 = 0,
        tr_addr_family_ipv6 = sock_transport_addr_shift(1)
    };

    enum socket_transport {
        tr_invalid  = 0,
        udp_ipv4 = tr_proto_udp,
        udp_ipv6 = tr_proto_udp | tr_addr_family_ipv6,
        tcp_ipv4 = tr_proto_tcp,
        tcp_ipv6 = tr_proto_tcp | tr_addr_family_ipv6,
        tls_ipv4 = tr_proto_tls,
        tls_ipv6 = tr_proto_tls | tr_addr_family_ipv6,
        ws_ipv4 =  tr_proto_ws,
        ws_ipv6 =  tr_proto_ws  | tr_addr_family_ipv6,
        wss_ipv4 = tr_proto_wss,
        wss_ipv6 = tr_proto_wss | tr_addr_family_ipv6
    };
    static const char *socket_transport2proto_str(const socket_transport transport);

    static int log_level_raw_msgs;

protected:
    // socket descriptor
    int sd;

    // bound address
    sockaddr_storage addr;

    // bound IP
    string           ip;

    // bound port number
    unsigned short   port;

    string actual_ip;
    unsigned short actual_port;

    // public IP (Via-HF)
    string      public_ip;
    // public domain IP (Via-HF)
    string      public_domain;
    // should we add port to Via-HF
    bool        announce_port;

    // internal interface number
    unsigned short   if_num;

    // internal interface protocol index
    unsigned short   proto_idx;

    // network interface index
    unsigned int sys_if_idx;

    // ORed field of socket_option
    unsigned int socket_options;

    // transport interface
    socket_transport transport;

    uint8_t tos_byte;

public:
	trsp_socket(unsigned short if_num, unsigned short proto_idx, unsigned int opts,
		socket_transport trans, unsigned int sys_if_idx = 0, int sd = 0);
    virtual ~trsp_socket();

    int set_tos_byte(uint8_t byte);

    /**
     * Binds the transport socket to an address
     * @return -1 if error(s) occured.
     */
    virtual int bind(const string& address, unsigned short port)=0;

    /**
     * Getter for the transport name
     */
    virtual const char* get_transport() const = 0;

    /**
     * Getter for the transport type
     */
    socket_transport get_transport_id() const { return transport; }

    /**
     * Getter for IP address
     */
    const char* get_ip() const;
    
    /**
     * Getter for the port number
     */
    unsigned short get_port() const;

    /**
     * Getter for actual IP address
     */
    const string &get_actual_ip() const;

    /**
     * Getter for the actual port number
     */
    unsigned short get_actual_port() const;


    /**
     * Getter for the socket_options
     */
    unsigned int get_options() const;


    /**
     * Setter for public IP address
     */
    void set_public_ip(const string& ip);

    /**
     * Setter for public domain address
     */
    void set_public_domain(const string& domain);

    /**
     * Setter for announce port flag
     */
    void set_announce_port(bool announce);

    /**
     * Getter for announce port flag
     */
    bool get_announce_port() const;

    /**
     * Getter for advertised Host
     * @return either bound IP or public IP or public Domain
     */
    const char* get_advertised_host() const;

    /**
     *  Getter for the socket descriptor
     */
    int get_sd() const;

    /**
     * Getter for the interface number
     */
    unsigned short get_if() const;

    /**
     * Getter for the interface addr number
     */
    unsigned short get_proto_idx() const;

    /**
     * Is the transport reliable?
     */
    virtual bool is_reliable() const { return false; }

    /**
     * Checks for socket options
     */
    bool is_opt_set(unsigned int mask) const;

    /**
     * Copy the internal address into the given one (sa).
     */
    void copy_addr_to(sockaddr_storage* sa) const;

    /**
     * Match with the given address
     * @return true if address matches
     */
    bool match_addr(sockaddr_storage* other_addr) const;

    /**
     * Sends a message.
     * @return -1 if error(s) occured.
     */
    virtual int send(const sockaddr_storage* sa, const char* msg, 
		     const int msg_len, unsigned int flags)=0;

	virtual void getInfo(AmArg &) {}

    virtual void inc_sip_parse_error() = 0;
};

class trsp_acl {
  public:
    enum action_t {
        Allow = 0,
        Drop,
        Reject
    };

  private:
    vector<AmSubnet> networks;
    action_t action;

  public:
    trsp_acl(): action(Reject) { }
    action_t check(const sockaddr_storage &ip) const;

    void set_action(action_t a) { action = a; }
    void add_network(AmSubnet net) { networks.push_back(net); }
};

struct trsp_acls {
    trsp_acl inv; //INVITE ACLs
    trsp_acl opt; //OPTIONS ACLs
    trsp_acl reg; //REGISTER ACLs
};

#endif

/** EMACS **
 * Local variables:
 * mode: c++
 * c-basic-offset: 4
 * End:
 */

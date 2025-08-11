/*
 * $Id: SipCtrlInterface.cpp 1648 2010-03-03 19:35:22Z sayer $
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
#include "SipCtrlInterface.h"

#include "AmUtils.h"
#include "AmSipMsg.h"
#include "AmMimeBody.h"
#include "AmSipHeaders.h"

#include "sip/trans_layer.h"
#include "sip/sip_parser.h"
#include "sip/parse_header.h"
#include "sip/parse_from_to.h"
#include "sip/parse_cseq.h"
#include "sip/parse_100rel.h"
#include "sip/parse_route.h"
#include "sip/trans_table.h"
#include "sip/sip_trans.h"
#include "sip/wheeltimer.h"
#include "sip/msg_hdrs.h"
#include "sip/udp_trsp.h"
#include "sip/ip_util.h"
#include "sip/tcp_trsp.h"
#include "sip/tls_trsp.h"
#include "sip/ws_trsp.h"

#include "log.h"

#include <assert.h>

#include "AmApi.h"
#include "AmSipDispatcher.h"
#include "AmEventDispatcher.h"
#include "AmSipEvent.h"
#include "AmLcConfig.h"

#include <functional>

bool _SipCtrlInterface::log_parsed_messages = true;
int  _SipCtrlInterface::udp_rcvbuf          = -1;

int _SipCtrlInterface::alloc_udp_structs()
{
    unsigned short socketsCount = 0;
    for (auto &interface : AmConfig.sip_ifs) {
        for (auto &info : interface.proto_info) {
            if (info->type == SIP_info::UDP) {
                socketsCount++;
            }
        }
    }
    udp_sockets = new udp_trsp_socket *[socketsCount];
    udp_servers = new udp_trsp *[AmConfig.sip_udp_server_threads];

    if (udp_sockets && udp_servers)
        return 0;

    return -1;
}

int _SipCtrlInterface::init_udp_sockets(unsigned short if_num, unsigned short proto_idx, SIP_info &info)
{
    trsp_socket::socket_transport trans;
    if (info.type_ip == AT_V4) {
        trans = trsp_socket::udp_ipv4;
    } else if (info.type_ip == AT_V6) {
        trans = trsp_socket::udp_ipv6;
    } else {
        ERROR("Unknown transport type in udp server");
        return -1;
    }

    udp_trsp_socket *udp_socket =
        new udp_trsp_socket(if_num, proto_idx,
                            info.sig_sock_opts | (AmConfig.force_outbound_if ? trsp_socket::force_outbound_if : 0) |
                                (info.sig_sock_opts & trsp_socket::use_raw_sockets ? trsp_socket::use_raw_sockets : 0),
                            trans, info.net_if_idx);

    if (!info.public_ip.empty()) {
        udp_socket->set_public_ip(info.public_ip);
    }
    udp_socket->set_public_domain(info.public_domain);
    udp_socket->set_announce_port(info.announce_port);

    if (udp_socket->bind(info.local_ip, info.local_port) < 0) {
        ERROR("Could not bind SIP/UDP socket to %s:%i", info.local_ip.c_str(), info.local_port);

        delete udp_socket;
        return -1;
    }

    if (udp_rcvbuf > 0) {
        udp_socket->set_recvbuf_size(udp_rcvbuf);
    }

    if (info.tos_byte) {
        udp_socket->set_tos_byte(info.tos_byte);
    }

    trans_layer::instance()->register_transport(udp_socket);
    udp_sockets[nr_udp_sockets] = udp_socket;
    inc_ref(udp_socket);
    nr_udp_sockets++;
    return 0;
}

int _SipCtrlInterface::init_udp_servers()
{
    for (int i = 0; i < AmConfig.sip_udp_server_threads; i++) {
        udp_servers[nr_udp_servers] = new udp_trsp();
        for (int j = 0; j < nr_udp_sockets; j++) {
            udp_servers[nr_udp_servers]->add_socket(udp_sockets[j]);
        }
        nr_udp_servers++;
    }
    return 0;
}

int _SipCtrlInterface::alloc_trsp_worker_structs()
{
    nr_trsp_workers = AmConfig.sip_tcp_server_threads;
    trsp_workers    = new trsp_worker *[nr_trsp_workers];
    if (trsp_workers) {
        return 0;
    }

    return -1;
}

int _SipCtrlInterface::init_trsp_workers()
{
    for (int i = 0; i < nr_trsp_workers; i++) {
        trsp_workers[i] = new trsp_worker();
    }
    return 0;
}

int _SipCtrlInterface::alloc_tcp_structs()
{
    unsigned short socketsCount = 0;
    for (auto &interface : AmConfig.sip_ifs) {
        for (auto &info : interface.proto_info) {
            if (info->type == SIP_info::TCP) {
                socketsCount++;
            }
        }
    }
    tcp_sockets = new tcp_server_socket *[socketsCount];

    if (tcp_sockets)
        return 0;

    return -1;
}

int _SipCtrlInterface::init_tcp_servers(unsigned short if_num, unsigned short proto_idx, SIP_info &info)
{
    trsp_socket::socket_transport trans;
    if (info.type_ip == AT_V4) {
        trans = trsp_socket::tcp_ipv4;
    } else if (info.type_ip == AT_V6) {
        trans = trsp_socket::tcp_ipv6;
    } else {
        ERROR("Unknown transport type in udp server");
        return -1;
    }
    tcp_server_socket *tcp_socket = new tcp_server_socket(if_num, proto_idx, info.sig_sock_opts, trans);

    if (!info.public_ip.empty()) {
        tcp_socket->set_public_ip(info.public_ip);
    }
    tcp_socket->set_public_domain(info.public_domain);
    tcp_socket->set_announce_port(info.announce_port);

    SIP_TCP_info *tcp_info = SIP_TCP_info::toSIP_TCP(&info);
    if (!tcp_info) {
        ERROR("incorrect type of sip info - not TCP");
        return -1;
    }
    tcp_socket->set_connect_timeout(tcp_info->tcp_connect_timeout);
    tcp_socket->set_idle_timeout(tcp_info->tcp_idle_timeout);

    if (tcp_socket->bind(info.local_ip, info.local_port) < 0) {
        ERROR("Could not bind SIP/TCP socket to %s:%i", info.local_ip.c_str(), info.local_port);

        delete tcp_socket;
        return -1;
    }

    if (info.tos_byte) {
        tcp_socket->set_tos_byte(info.tos_byte);
    }

    // TODO: add some more threads
    tcp_socket->add_workers(trsp_workers, nr_trsp_workers);

    trans_layer::instance()->register_transport(tcp_socket);
    tcp_sockets[nr_tcp_sockets] = tcp_socket;
    inc_ref(tcp_socket);
    nr_tcp_sockets++;

    trsp_server->add_socket(tcp_socket);
    return 0;
}

int _SipCtrlInterface::alloc_tls_structs()
{
    unsigned short socketsCount = 0;
    for (auto &interface : AmConfig.sip_ifs) {
        for (auto &info : interface.proto_info) {
            if (info->type == SIP_info::TLS) {
                socketsCount++;
            }
        }
    }
    tls_sockets = new tls_server_socket *[socketsCount];

    if (tls_sockets)
        return 0;

    return -1;
}

int _SipCtrlInterface::init_tls_servers(unsigned short if_num, unsigned short proto_idx, SIP_info &info)
{
    trsp_socket::socket_transport trans;
    if (info.type_ip == AT_V4) {
        trans = trsp_socket::tls_ipv4;
    } else if (info.type_ip == AT_V6) {
        trans = trsp_socket::tls_ipv6;
    } else {
        ERROR("Unknown transport type in tls server");
        return -1;
    }

    SIP_TLS_info *tls_info = SIP_TLS_info::toSIP_TLS(&info);
    if (!tls_info) {
        ERROR("incorrect type of sip info - not TCP");
        return -1;
    }

    tls_server_socket *tls_socket = 0;
    try {
        tls_socket = new tls_server_socket(if_num, proto_idx, info.sig_sock_opts, trans);
    } catch (Botan::Exception &ex) {
        ERROR("Botan Exception: %s", ex.what());
    }

    if (!tls_socket) {
        return -1;
    }

    if (!info.public_ip.empty()) {
        tls_socket->set_public_ip(info.public_ip);
    }
    tls_socket->set_public_domain(info.public_domain);
    tls_socket->set_announce_port(info.announce_port);

    tls_socket->set_connect_timeout(tls_info->tcp_connect_timeout);
    tls_socket->set_idle_timeout(tls_info->tcp_idle_timeout);

    if (tls_socket->bind(info.local_ip, info.local_port) < 0) {
        ERROR("Could not bind SIP/TCP socket to %s:%i", info.local_ip.c_str(), info.local_port);

        delete tls_socket;
        return -1;
    }

    if (info.tos_byte) {
        tls_socket->set_tos_byte(info.tos_byte);
    }

    // TODO: add some more threads
    tls_socket->add_workers(trsp_workers, nr_trsp_workers);

    trans_layer::instance()->register_transport(tls_socket);
    tls_sockets[nr_tls_sockets] = tls_socket;
    inc_ref(tls_socket);
    nr_tls_sockets++;

    trsp_server->add_socket(tls_socket);

    return 0;
}

int _SipCtrlInterface::alloc_ws_structs()
{
    unsigned short socketsCount = 0;
    for (auto &interface : AmConfig.sip_ifs) {
        for (auto &info : interface.proto_info) {
            if (info->type == SIP_info::WS) {
                socketsCount++;
            }
        }
    }
    ws_sockets = new ws_server_socket *[socketsCount];

    if (ws_sockets)
        return 0;

    return -1;
}

int _SipCtrlInterface::init_ws_servers(unsigned short if_num, unsigned short proto_idx, SIP_info &info)
{
    trsp_socket::socket_transport trans;
    if (info.type_ip == AT_V4) {
        trans = trsp_socket::ws_ipv4;
    } else if (info.type_ip == AT_V6) {
        trans = trsp_socket::ws_ipv6;
    } else {
        ERROR("Unknown transport type in ws server");
        return -1;
    }

    SIP_WS_info *ws_info = SIP_WS_info::toSIP_WS(&info);
    if (!ws_info) {
        ERROR("incorrect type of sip info - not WS");
        return -1;
    }

    ws_server_socket *ws_socket = new ws_server_socket(if_num, proto_idx, info.sig_sock_opts, trans);

    if (!ws_socket) {
        return -1;
    }

    if (!info.public_ip.empty()) {
        ws_socket->set_public_ip(info.public_ip);
    }
    ws_socket->set_public_domain(info.public_domain);
    ws_socket->set_announce_port(info.announce_port);

    ws_socket->set_connect_timeout(ws_info->tcp_connect_timeout);
    ws_socket->set_idle_timeout(ws_info->tcp_idle_timeout);

    if (ws_socket->bind(info.local_ip, info.local_port) < 0) {
        ERROR("Could not bind SIP/WS socket to %s:%i", info.local_ip.c_str(), info.local_port);

        delete ws_socket;
        return -1;
    }

    if (info.tos_byte) {
        ws_socket->set_tos_byte(info.tos_byte);
    }

    // TODO: add some more threads
    ws_socket->add_workers(trsp_workers, nr_trsp_workers);

    trans_layer::instance()->register_transport(ws_socket);
    ws_sockets[nr_ws_sockets] = ws_socket;
    inc_ref(ws_socket);
    nr_ws_sockets++;

    trsp_server->add_socket(ws_socket);

    return 0;
}

int _SipCtrlInterface::alloc_wss_structs()
{
    unsigned short socketsCount = 0;
    for (auto &interface : AmConfig.sip_ifs) {
        for (auto &info : interface.proto_info) {
            if (info->type == SIP_info::WSS) {
                socketsCount++;
            }
        }
    }
    wss_sockets = new wss_server_socket *[socketsCount];

    if (wss_sockets)
        return 0;

    return -1;
}

int _SipCtrlInterface::init_wss_servers(unsigned short if_num, unsigned short proto_idx, SIP_info &info)
{
    trsp_socket::socket_transport trans;
    if (info.type_ip == AT_V4) {
        trans = trsp_socket::wss_ipv4;
    } else if (info.type_ip == AT_V6) {
        trans = trsp_socket::wss_ipv6;
    } else {
        ERROR("Unknown transport type in wss server");
        return -1;
    }

    SIP_WSS_info *wss_info = SIP_WSS_info::toSIP_WSS(&info);
    if (!wss_info) {
        ERROR("incorrect type of sip info - not WSS");
        return -1;
    }

    wss_server_socket *wss_socket = 0;
    try {
        wss_socket = new wss_server_socket(if_num, proto_idx, info.sig_sock_opts, trans);
    } catch (Botan::Exception &ex) {
        ERROR("Botan Exception: %s", ex.what());
    }

    if (!wss_socket) {
        return -1;
    }

    if (!info.public_ip.empty()) {
        wss_socket->set_public_ip(info.public_ip);
    }
    wss_socket->set_public_domain(info.public_domain);
    wss_socket->set_announce_port(info.announce_port);

    wss_socket->set_connect_timeout(wss_info->tcp_connect_timeout);
    wss_socket->set_idle_timeout(wss_info->tcp_idle_timeout);

    if (wss_socket->bind(info.local_ip, info.local_port) < 0) {
        ERROR("Could not bind SIP/TCP socket to %s:%i", info.local_ip.c_str(), info.local_port);

        delete wss_socket;
        return -1;
    }

    if (info.tos_byte) {
        wss_socket->set_tos_byte(info.tos_byte);
    }

    // TODO: add some more threads
    wss_socket->add_workers(trsp_workers, nr_trsp_workers);

    trans_layer::instance()->register_transport(wss_socket);
    wss_sockets[nr_wss_sockets] = wss_socket;
    inc_ref(wss_socket);
    nr_wss_sockets++;

    trsp_server->add_socket(wss_socket);

    return 0;
}

int _SipCtrlInterface::load()
{
    if (!AmConfig.outbound_proxy.empty()) {
        sip_uri parsed_uri;
        if (parse_uri(&parsed_uri, (char *)AmConfig.outbound_proxy.c_str(), AmConfig.outbound_proxy.length()) < 0) {
            ERROR("invalid outbound_proxy specified");
            return -1;
        }
    }

    if (alloc_udp_structs() < 0) {
        ERROR("no enough memory to alloc UDP structs");
        return -1;
    }

    // Init UDP transport instances
    unsigned short udp_idx = 0;
    for (auto &interface : AmConfig.sip_ifs) {
        unsigned short proto_idx = 0;
        for (auto &info : interface.proto_info) {
            if (info->type == SIP_info::UDP) {
                if (init_udp_sockets(udp_idx, proto_idx, *info) < 0) {
                    return -1;
                }
            }
            proto_idx++;
        }
        udp_idx++;
    }

    if (init_udp_servers() < 0) {
        return -1;
    }

    if (alloc_trsp_worker_structs() < 0) {
        ERROR("no enough memory to alloc sip workers structs");
        return -1;
    }

    if (init_trsp_workers() < 0) {
        return -1;
    }

    trsp_server = new trsp();

    if (alloc_tcp_structs() < 0) {
        ERROR("no enough memory to alloc TCP structs");
        return -1;
    }

    // Init TCP transport instances
    unsigned short tcp_idx = 0;
    for (auto &interface : AmConfig.sip_ifs) {
        unsigned short proto_idx = 0;
        for (auto &info : interface.proto_info) {
            if (info->type == SIP_info::TCP) {
                if (init_tcp_servers(tcp_idx, proto_idx, *info) < 0) {
                    return -1;
                }
            }
            proto_idx++;
        }
        tcp_idx++;
    }

    if (alloc_ws_structs() < 0) {
        ERROR("no enough memory to alloc WS structs");
        return -1;
    }

    // Init WS transport instances
    unsigned short ws_idx = 0;
    for (auto &interface : AmConfig.sip_ifs) {
        unsigned short proto_idx = 0;
        for (auto &info : interface.proto_info) {
            if (info->type == SIP_info::WS) {
                if (init_ws_servers(ws_idx, proto_idx, *info) < 0) {
                    return -1;
                }
            }
            proto_idx++;
        }
        ws_idx++;
    }

    if (alloc_tls_structs() < 0) {
        ERROR("no enough memory to alloc TLS structs");
        return -1;
    }

    // Init TLS transport instances
    unsigned short tls_idx = 0;
    for (auto &interface : AmConfig.sip_ifs) {
        unsigned short proto_idx = 0;
        for (auto &info : interface.proto_info) {
            if (info->type == SIP_info::TLS) {
                if (init_tls_servers(tls_idx, proto_idx, *info) < 0) {
                    return -1;
                }
            }
            proto_idx++;
        }
        tls_idx++;
    }

    if (alloc_wss_structs() < 0) {
        ERROR("no enough memory to alloc WSS structs");
        return -1;
    }

    // Init WSS transport instances
    unsigned short wss_idx = 0;
    for (auto &interface : AmConfig.sip_ifs) {
        unsigned short proto_idx = 0;
        for (auto &info : interface.proto_info) {
            if (info->type == SIP_info::WSS) {
                if (init_wss_servers(wss_idx, proto_idx, *info) < 0) {
                    return -1;
                }
            }
            proto_idx++;
        }
        wss_idx++;
    }

    auto &queue_size_group =
        stat_group(Gauge, "core", "transport_send_queue_size").setHelp("Connections sending queues size sum");

    if (nr_tcp_sockets || nr_tls_sockets || nr_ws_sockets || nr_wss_sockets) {
        queue_size_group
            .addFunctionCounter([]() -> unsigned long long { return SipCtrlInterface::instance()->getTcpQueueSize(); })
            .addLabel("transport", "tcp");
    }
    if (nr_tls_sockets || nr_wss_sockets) {
        queue_size_group
            .addFunctionCounter([]() -> unsigned long long { return SipCtrlInterface::instance()->getTlsQueueSize(); })
            .addLabel("transport", "tls");
    }
    if (nr_ws_sockets) {
        queue_size_group
            .addFunctionCounter([]() -> unsigned long long { return SipCtrlInterface::instance()->getWsQueueSize(); })
            .addLabel("transport", "ws");
    }
    if (nr_wss_sockets) {
        queue_size_group
            .addFunctionCounter([]() -> unsigned long long { return SipCtrlInterface::instance()->getWssQueueSize(); })
            .addLabel("transport", "wss");
    }

    stat_group(Gauge, "core", "transport_accept_queue_size")
        .setHelp("Transport workers libevent accept queue size")
        .addFunctionGroupCounter([](StatCounterInterface::iterate_func_type f) {
            SipCtrlInterface *sip_ctrl = SipCtrlInterface::instance();
            for (int i = 0; i < sip_ctrl->nr_tcp_sockets; i++) {
                tcp_server_socket *socket = sip_ctrl->tcp_sockets[i];
                socket->getAcceptQueueSize(f);
            }
            for (int i = 0; i < sip_ctrl->nr_tls_sockets; i++) {
                tls_server_socket *socket = sip_ctrl->tls_sockets[i];
                socket->getAcceptQueueSize(f);
            }
            for (int i = 0; i < sip_ctrl->nr_ws_sockets; i++) {
                ws_server_socket *socket = sip_ctrl->ws_sockets[i];
                socket->getAcceptQueueSize(f);
            }
            for (int i = 0; i < sip_ctrl->nr_wss_sockets; i++) {
                wss_server_socket *socket = sip_ctrl->wss_sockets[i];
                socket->getAcceptQueueSize(f);
            }
        });

    return 0;
}

_SipCtrlInterface::_SipCtrlInterface()
    : stopped(false)
    , nr_udp_sockets(0)
    , udp_sockets(NULL)
    , nr_udp_servers(0)
    , udp_servers(NULL)
    , nr_tcp_sockets(0)
    , tcp_sockets(NULL)
    , nr_tls_sockets(0)
    , tls_sockets(NULL)
    , nr_ws_sockets(0)
    , ws_sockets(NULL)
    , nr_wss_sockets(0)
    , wss_sockets(NULL)
    , nr_trsp_workers(0)
    , trsp_workers(NULL)
    , trsp_server(NULL)
{
    trans_layer::instance()->register_ua(this);
}

_SipCtrlInterface::~_SipCtrlInterface()
{
    AmSipDispatcher::dispose();
    trans_layer::dispose();
}

int _SipCtrlInterface::cancel(trans_ticket *tt, const string &dialog_id, unsigned int inv_cseq, unsigned int maxf,
                              const string &hdrs, const string &dlg_route_set)
{
    return trans_layer::instance()->cancel(tt, stl2cstr(dialog_id), inv_cseq, maxf, stl2cstr(hdrs),
                                           stl2cstr(dlg_route_set));
}

int _SipCtrlInterface::send(AmSipRequest &req, const string &dialog_id, const string &next_hop, int out_interface,
                            unsigned int flags, sip_target_set *target_set_override, msg_logger *logger,
                            msg_sensor *sensor, sip_timers_override *timers_override, int redirects_allowed)
{
    std::unique_ptr<sip_target_set> target_set(target_set_override);

    if (req.max_forwards < 0) {
        req.max_forwards = AmConfig.max_forwards;
    }

    if (req.method == "CANCEL") {
        return cancel(&req.tt, dialog_id, req.cseq, req.max_forwards, req.hdrs, string());
    }

    sip_msg *msg = new sip_msg();

    msg->type      = SIP_REQUEST;
    msg->u.request = new sip_request();

    msg->u.request->method_str = stl2cstr(req.method);
    msg->u.request->ruri_str   = stl2cstr(req.r_uri);

    // To
    // From
    // Call-ID
    // CSeq
    // Contact
    // Max-Forwards

    const char *err_msg;
    char       *c   = (char *)req.from.c_str();
    int         err = parse_headers(msg, &c, c + req.from.length(), err_msg);

    c   = (char *)req.to.c_str();
    err = err || parse_headers(msg, &c, c + req.to.length(), err_msg);

    if (err) {
        ERROR("Malformed To or From header");
        delete msg;
        return -1;
    }

    string cseq = int2str(req.cseq) + " " + req.method;

    msg->cseq = new sip_header(0, SIP_HDR_CSEQ, stl2cstr(cseq));
    msg->hdrs.push_back(msg->cseq);

    msg->callid = new sip_header(0, SIP_HDR_CALL_ID, stl2cstr(req.callid));
    msg->hdrs.push_back(msg->callid);

    if (!req.contact.empty()) {

        c   = (char *)req.contact.c_str();
        err = parse_headers(msg, &c, c + req.contact.length(), err_msg);
        if (err) {
            ERROR("Malformed Contact header");
            delete msg;
            return -1;
        }
    }

    if (!req.route.empty()) {

        c   = (char *)req.route.c_str();
        err = parse_headers(msg, &c, c + req.route.length(), err_msg);

        if (err) {
            ERROR("Route headers parsing failed");
            ERROR("Faulty headers were: <%s>", req.route.c_str());
            delete msg;
            return -1;
        }
    }

    string mf = int2str(req.max_forwards);
    msg->hdrs.push_back(new sip_header(0, SIP_HDR_MAX_FORWARDS, stl2cstr(mf)));

    if (!req.hdrs.empty()) {

        c = (char *)req.hdrs.c_str();

        err = parse_headers(msg, &c, c + req.hdrs.length(), err_msg);

        if (err) {
            ERROR("Additional headers parsing failed");
            ERROR("Faulty headers were: <%s>", req.hdrs.c_str());
            delete msg;
            return -1;
        }
    }

    string body;
    string content_type;

    if (!req.body.empty()) {
        content_type      = req.body.getCTHdr();
        msg->content_type = new sip_header(0, SIP_HDR_CONTENT_TYPE, stl2cstr(content_type));
        msg->hdrs.push_back(msg->content_type);
        req.body.print(body);
        msg->body = stl2cstr(body);
    }

    int res = trans_layer::instance()->send_request(msg, &req.tt, stl2cstr(dialog_id), stl2cstr(next_hop),
                                                    out_interface, flags, logger, sensor, timers_override,
                                                    target_set.release(), redirects_allowed);
    delete msg;

    return res;
}

int _SipCtrlInterface::run()
{
    DBG("Starting SIP control interface");

    wheeltimer::instance()->start();
    AmThreadWatcher::instance()->add(wheeltimer::instance());

    if (NULL != udp_servers) {
        for (int i = 0; i < nr_udp_servers; i++) {
            udp_servers[i]->start();
        }
    }

    if (NULL != trsp_workers) {
        for (int i = 0; i < nr_trsp_workers; i++) {
            trsp_workers[i]->start();
        }
    }

    if (NULL != trsp_server) {
        trsp_server->start();
    }

    while (!stopped.get()) {
        stopped.wait_for();
    }

    DBG("SIP control interface ending");
    return 0;
}

void _SipCtrlInterface::stop()
{
    stopped.set(true);
}

template <typename T> void cleanup_array(T *&v, unsigned short &n, std::function<void(int)> f)
{
    if (v == nullptr)
        return;

    for (int i = 0; i < n; i++)
        f(i);

    delete[] v;
    v = nullptr;
    n = 0;
}

template <typename T> void cleanup_with_stop_delete(T *&workers, unsigned short &n)
{
    cleanup_array(workers, n, [&workers](int i) {
        workers[i]->stop(true);
        delete workers[i];
    });
}

template <typename T> void cleanup_with_decref(T *&sockets, unsigned short &n)
{
    cleanup_array(sockets, n, [&sockets](int i) {
        DBG("dec_ref(%p)", sockets[i]);
        dec_ref(sockets[i]);
    });
}

void _SipCtrlInterface::cleanup()
{
    DBG("Stopping SIP control interface threads");

    if (NULL != trsp_server) {
        trsp_server->stop();
        trsp_server->join();
    }

    cleanup_with_stop_delete(trsp_workers, nr_trsp_workers);
    cleanup_with_stop_delete(udp_servers, nr_udp_servers);

    trans_layer::instance()->clear_transports();

    cleanup_with_decref(udp_sockets, nr_udp_sockets);
    cleanup_with_decref(tcp_sockets, nr_tcp_sockets);
    cleanup_with_decref(ws_sockets, nr_ws_sockets);
    cleanup_with_decref(tls_sockets, nr_tls_sockets);
    cleanup_with_decref(wss_sockets, nr_wss_sockets);

    if (NULL != trsp_server) {
        delete trsp_server;
        trsp_server = NULL;
    }
}

int _SipCtrlInterface::send(const AmSipReply &rep, const string &dialog_id, msg_logger *logger, msg_sensor *sensor)
{
    sip_msg     msg;
    const char *err_msg;

    if (!rep.hdrs.empty()) {

        char *c   = (char *)rep.hdrs.c_str();
        int   err = parse_headers(&msg, &c, c + rep.hdrs.length(), err_msg);
        if (err) {
            ERROR("Malformed additional header");
            return -1;
        }
    }

    if (!rep.contact.empty()) {

        char *c   = (char *)rep.contact.c_str();
        int   err = parse_headers(&msg, &c, c + rep.contact.length(), err_msg);
        if (err) {
            ERROR("Malformed Contact header");
            return -1;
        }
    }

    string body;
    string content_type;
    if (!rep.body.empty()) {
        content_type = rep.body.getCTHdr();
        rep.body.print(body);
        if (content_type.empty()) {
            ERROR("Reply does not contain a Content-Type whereby body is not empty");
            return -1;
        }
        msg.body = stl2cstr(body);
        msg.hdrs.push_back(new sip_header(sip_header::H_CONTENT_TYPE, SIP_HDR_CONTENT_TYPE, stl2cstr(content_type)));
    }

    msg.type    = SIP_REPLY;
    msg.u.reply = new sip_reply(rep.code, stl2cstr(rep.reason));

    return trans_layer::instance()->send_reply(&msg, (trans_ticket *)&rep.tt, stl2cstr(dialog_id), stl2cstr(rep.to_tag),
                                               logger, sensor);
}


void prepare_routes_uac(const list<sip_header *> &routes, string &route_field);
void prepare_routes_uas(const list<sip_header *> &routes, string &route_field);

bool _SipCtrlInterface::sip_msg2am_request(
    const sip_msg *msg, std::function<void(const sip_msg *req, int reply_code, const cstring &reason)> callback,
    AmSipRequest &req)
{
    assert(msg);
    assert(msg->from && msg->from->p);
    assert(msg->to && msg->to->p);

    if (msg->u.request->ruri.scheme == sip_uri::SIPS)
        req.scheme = "sips";
    else if (msg->u.request->ruri.scheme == sip_uri::SIP)
        req.scheme = "sip";
    req.method = c2stlstr(msg->u.request->method_str);
    req.user   = c2stlstr(msg->u.request->ruri.user);
    req.domain = c2stlstr(msg->u.request->ruri.host);
    req.r_uri  = c2stlstr(msg->u.request->ruri_str);

    if (get_contact(msg) && get_contact(msg)->value.len) {
        sip_nameaddr na;
        cstring      contact = get_contact(msg)->value;
        if (parse_first_nameaddr(&na, contact.s, contact.len) < 0) {
            WARN("Contact parsing failed");
            WARN("\tcontact = '%.*s'", contact.len, contact.s);
            WARN("\trequest = '%.*s'", msg->len, msg->buf);

            callback(msg, 400, "Bad Contact");
            return false;
        }

        const char *c = na.addr.s;
        if ((na.addr.len != 1) || (*c != '*')) {
            sip_uri u;
            if (parse_uri(&u, na.addr.s, na.addr.len)) {
                DBG("'Contact' in new request contains a malformed URI");
                DBG("\tcontact uri = '%.*s'", na.addr.len, na.addr.s);
                DBG("\trequest = '%.*s'", msg->len, msg->buf);

                callback(msg, 400, "Malformed Contact URI");
                return false;
            }

            req.from_uri = c2stlstr(na.addr);
        }

        list<sip_header *>::const_iterator c_it = msg->contacts.begin();
        req.contact                             = c2stlstr((*c_it)->value);
        ++c_it;

        for (; c_it != msg->contacts.end(); ++c_it) {
            req.contact += ", " + c2stlstr((*c_it)->value);
        }
    } else {
        if (req.method == SIP_METH_INVITE) {
            DBG("Request has no contact header");
            DBG("\trequest = '%.*s'", msg->len, msg->buf);
            callback(msg, 400, "Missing Contact-HF");
            return false;
        }
    }

    if (req.from_uri.empty()) {
        req.from_uri = c2stlstr(get_from(msg)->nameaddr.addr);
    }

    if (get_from(msg)->nameaddr.name.len) {
        req.from += c2stlstr(get_from(msg)->nameaddr.name) + ' ';
    }

    req.from += '<' + c2stlstr(get_from(msg)->nameaddr.addr) + '>';

    req.to          = c2stlstr(msg->to->value);
    req.callid      = c2stlstr(msg->callid->value);
    req.from_tag    = c2stlstr(((sip_from_to *)msg->from->p)->tag);
    req.to_tag      = c2stlstr(((sip_from_to *)msg->to->p)->tag);
    req.cseq        = get_cseq(msg)->num;
    req.cseq_method = c2stlstr(get_cseq(msg)->method_str);
    req.via_branch  = c2stlstr(msg->via_p1->branch);

    if (msg->rack) {
        req.rseq        = get_rack(msg)->rseq;
        req.rack_method = c2stlstr(get_rack(msg)->method_str);
        req.rack_cseq   = get_rack(msg)->cseq;
    }

    if (msg->content_type && msg->body.len) {
        if (req.body.parse(c2stlstr(msg->content_type->value), (unsigned char *)msg->body.s, msg->body.len) < 0) {
            DBG("could not parse MIME body");
        } else {
            DBG3("MIME body successfully parsed");
            // some debug infos?
        }
    }

    prepare_routes_uas(msg->record_route, req.route);

    for (const auto &h : msg->hdrs) {
        switch (h->type) {
        case sip_header::H_OTHER:
        case sip_header::H_EXPIRES:
        case sip_header::H_REQUIRE:
        {
            string value = c2stlstr(h->value);
            size_t rpos  = 0;
            while ((rpos = value.find_first_of("\r\n", rpos)) != string::npos)
                value.erase(rpos, 1);
            req.hdrs += c2stlstr(h->name) + COLSP + value + CRLF;
        } break;
        case sip_header::H_VIA: req.vias += c2stlstr(h->name) + ": " + c2stlstr(h->value) + CRLF; break;
        case sip_header::H_MAX_FORWARDS:
            if (!str2int(c2stlstr(h->value), req.max_forwards) || (req.max_forwards < 0) || (req.max_forwards > 255)) {
                callback(msg, 400, "Incorrect Max-Forwards");
                return false;
            }
            break;
        }
    }

    if (req.max_forwards < 0)
        req.max_forwards = AmConfig.max_forwards;

    req.remote_ip   = get_addr_str(&msg->remote_ip);
    req.remote_port = am_get_port(&msg->remote_ip);

    req.local_ip   = get_addr_str(&msg->local_ip);
    req.local_port = am_get_port(&msg->local_ip);

    req.via1 = c2stlstr(msg->via1->value);
    if (msg->vias.size() > 1) {
        req.first_hop = false;
    } else {
        sip_via *via1 = (sip_via *)msg->via1->p;
        assert(via1); // gets parsed in parse_sip_msg()
        req.first_hop = (via1->parms.size() == 1);
    }

    req.recv_timestamp = msg->recv_timestamp;
    req.transport_id   = msg->transport_id;

    if (msg->local_socket) {
        req.trsp        = msg->local_socket->get_transport();
        req.local_if    = msg->local_socket->get_if();
        req.proto_idx   = msg->local_socket->get_proto_idx();
        req.actual_ip   = msg->local_socket->get_actual_ip();
        req.actual_port = msg->local_socket->get_actual_port();
    }

    return true;
}

bool _SipCtrlInterface::sip_msg2am_reply(const sip_msg *msg, AmSipReply &reply)
{
    if (msg->content_type) {

        if (reply.body.parse(c2stlstr(msg->content_type->value), (unsigned char *)msg->body.s, msg->body.len) < 0) {
            DBG("could not parse MIME body");
        } else {
            DBG("MIME body successfully parsed");
            // some debug infos?
        }
    }

    reply.cseq        = get_cseq(msg)->num;
    reply.cseq_method = c2stlstr(get_cseq(msg)->method_str);

    reply.code        = msg->u.reply->code;
    reply.reason      = c2stlstr(msg->u.reply->reason);
    reply.local_reply = msg->u.reply->local_reply;

    if (get_contact(msg) && get_contact(msg)->value.len) {

        // parse the first contact
        sip_nameaddr na;
        cstring      contact = get_contact(msg)->value;
        if (parse_first_nameaddr(&na, contact.s, contact.len) < 0) {
            WARN("Contact nameaddr parsing failed ('%.*s')", contact.len, contact.s);
        } else {
            reply.to_uri = c2stlstr(na.addr);
        }

        auto c_it     = msg->contacts.begin();
        reply.contact = c2stlstr((*c_it)->value);
        ++c_it;

        for (; c_it != msg->contacts.end(); ++c_it) {
            reply.contact += "," + c2stlstr((*c_it)->value);
        }
    }

    reply.callid = c2stlstr(msg->callid->value);

    reply.to_tag   = c2stlstr(((sip_from_to *)msg->to->p)->tag);
    reply.from_tag = c2stlstr(((sip_from_to *)msg->from->p)->tag);


    prepare_routes_uac(msg->record_route, reply.route);

    unsigned rseq;
    for (const auto &h : msg->hdrs) {
#ifdef PROPAGATE_UNPARSED_REPLY_HEADERS
        reply.unparsed_headers.push_back(AmSipHeader((*it)->name, (*it)->value));
#endif
        switch (h->type) {
        case sip_header::H_OTHER:
        case sip_header::H_EXPIRES:
        case sip_header::H_REQUIRE:
        {
            string value = c2stlstr(h->value);
            size_t rpos  = 0;
            while ((rpos = value.find_first_of("\r\n", rpos)) != string::npos)
                value.erase(rpos, 1);
            reply.hdrs += c2stlstr(h->name) + COLSP + value + CRLF;
        } break;
        case sip_header::H_RSEQ:
            if (!parse_rseq(&rseq, h->value.s, static_cast<int>(h->value.len))) {
                ERROR("failed to parse (rcvd) '" SIP_HDR_RSEQ "' hdr.");
            } else {
                reply.rseq = rseq;
            }
            break;
        }
    }

    reply.remote_ip   = get_addr_str(&msg->remote_ip);
    reply.remote_port = am_get_port(&msg->remote_ip);

    reply.local_ip   = get_addr_str(&msg->local_ip);
    reply.local_port = am_get_port(&msg->local_ip);

    reply.recv_timestamp = msg->recv_timestamp;
    reply.transport_id   = msg->transport_id;

    if (msg->local_socket) {
        reply.actual_ip   = msg->local_socket->get_actual_ip();
        reply.actual_port = msg->local_socket->get_actual_port();
    }

    return true;
}


#define DBG_PARAM(p) DBG3("%s = <%s>", #p, p.c_str());

void _SipCtrlInterface::handle_sip_request(const trans_ticket &tt, sip_msg *msg)
{
    assert(msg);
    assert(msg->from && msg->from->p);
    assert(msg->to && msg->to->p);

    AmSipRequest req;
    if (!req.init(msg, &tt))
        return;

    DBG("Received new request from <%s:%i/%s> on intf #%i", req.remote_ip.c_str(), req.remote_port, req.trsp.c_str(),
        req.local_if);

    if (_SipCtrlInterface::log_parsed_messages) {
        //     DBG_PARAM(req.cmd);
        DBG_PARAM(req.method);
        //     DBG_PARAM(req.user);
        //     DBG_PARAM(req.domain);
        DBG_PARAM(req.r_uri);
        DBG_PARAM(req.from_uri);
        DBG_PARAM(req.from);
        DBG_PARAM(req.to);
        DBG_PARAM(req.callid);
        DBG_PARAM(req.from_tag);
        DBG_PARAM(req.to_tag);
        DBG3("cseq = <%i>", req.cseq);
        DBG_PARAM(req.route);
        DBG3("hdrs = <%s>", req.hdrs.c_str());
        DBG3("body-ct = <%s>", req.body.getCTStr().c_str());
    }

    AmSipDispatcher::instance()->handleSipMsg(req);

    DBG("^^ M [%s|%s] Ru SIP request %s handled ^^", req.callid.c_str(), req.to_tag.c_str(), req.method.c_str());
}

void _SipCtrlInterface::handle_sip_reply(const trans_ticket &tt, const string &dialog_id, sip_msg *msg)
{
    assert(msg->from && msg->from->p);
    assert(msg->to && msg->to->p);

    AmSipReply reply;
    if (!reply.init(msg)) {
        ERROR("failed to convert sip_msg to AmSipReply");
        // trans_bucket::match_reply only uses via_branch & cseq
        reply.cseq        = get_cseq(msg)->num;
        reply.cseq_method = c2stlstr(get_cseq(msg)->method_str);
        reply.code        = 500;
        reply.reason      = "Internal Server Error";
        reply.callid      = c2stlstr(msg->callid->value);
        reply.to_tag      = c2stlstr(((sip_from_to *)msg->to->p)->tag);
        reply.from_tag    = c2stlstr(((sip_from_to *)msg->from->p)->tag);
        AmSipDispatcher::instance()->handleSipMsg(dialog_id, reply);
        return;
    }

    reply.tt = tt;

    DBG("Received reply: %i %s", reply.code, reply.reason.c_str());
    DBG_PARAM(reply.callid);
    DBG_PARAM(reply.from_tag);
    DBG_PARAM(reply.to_tag);
    DBG_PARAM(reply.contact);
    DBG_PARAM(reply.to_uri);
    DBG("cseq = <%i>", reply.cseq);
    DBG_PARAM(reply.route);
    DBG("hdrs = <%s>", reply.hdrs.c_str());
    DBG("body-ct = <%s>", reply.body.getCTStr().c_str());

    AmSipDispatcher::instance()->handleSipMsg(dialog_id, reply);

    DBG("^^ M [%s|%s] ru SIP reply %u %s handled ^^", reply.callid.c_str(), reply.from_tag.c_str(), reply.code,
        reply.reason.c_str());
}

void _SipCtrlInterface::handle_reply_timeout(AmSipTimeoutEvent::EvType evt, sip_trans *tr, trans_bucket *buk)
{
    AmSipTimeoutEvent *tmo_evt;

    switch (evt) {
    case AmSipTimeoutEvent::noACK:
    {
        sip_cseq *cseq = dynamic_cast<sip_cseq *>(tr->msg->cseq->p);

        if (!cseq) {
            ERROR("missing CSeq");
            return;
        }
        tmo_evt = new AmSipTimeoutEvent(evt, cseq->num);
    } break;

    case AmSipTimeoutEvent::noPRACK:
    {
        sip_msg msg(tr->retr_buf, tr->retr_len);

        const char *err_msg = 0;
        int         err     = parse_sip_msg(&msg, err_msg);
        if (err) {
            ERROR("failed to parse (own) reply[%d]: %s.", err, err_msg ? err_msg : "???");
            return;
        }

        AmSipReply reply;
        if (!reply.init(&msg)) {
            ERROR("failed to convert sip_msg to AmSipReply.");
            return;
        }

        AmSipRequest request;
        trans_ticket tt_ = trans_ticket(tr, buk);
        request.init(tr->msg, &tt_);

        DBG("Reply timed out: %i %s", reply.code, reply.reason.c_str());
        DBG_PARAM(reply.callid);
        DBG_PARAM(reply.to_tag);
        DBG_PARAM(reply.from_tag);
        DBG("cseq = <%i>", reply.cseq);

        tmo_evt = new AmSipTimeoutEvent(evt, request, reply);
    } break;

    default: ERROR("BUG: unexpected timout event type '%d'.", evt); return;
    }

    cstring dlg_id = tr->to_tag;
    if (tr->dialog_id.len) {
        dlg_id = tr->dialog_id;
    }

    if (!AmEventDispatcher::instance()->post(c2stlstr(dlg_id), tmo_evt)) {
        DBG("Could not post timeout event (sess. id: %.*s)", dlg_id.len, dlg_id.s);
        delete tmo_evt;
    }
}

#undef DBG_PARAM

void prepare_routes_uac(const list<sip_header *> &routes, string &route_field)
{
    if (routes.empty())
        return;

    list<sip_header *>::const_reverse_iterator it_rh = routes.rbegin();
    if (parse_route(*it_rh) < 0) {
        DBG("Could not parse route header [%.*s]", (*it_rh)->value.len, (*it_rh)->value.s);
        return;
    }
    sip_route *route = (sip_route *)(*it_rh)->p;

    list<route_elmt *>::const_reverse_iterator it_re = route->elmts.rbegin();
    route_field                                      = c2stlstr((*it_re)->route);

    while (true) {

        if (++it_re == route->elmts.rend()) {
            if (++it_rh == routes.rend()) {
                DBG("route_field = [%s]", route_field.c_str());
                return;
            }

            if (parse_route(*it_rh) < 0) {
                DBG("Could not parse route header [%.*s]", (*it_rh)->value.len, (*it_rh)->value.s);
                return;
            }
            route = (sip_route *)(*it_rh)->p;
            if (route->elmts.empty())
                return;
            it_re = route->elmts.rbegin();
        }

        route_field += ", " + c2stlstr((*it_re)->route);
    }
}

void prepare_routes_uas(const list<sip_header *> &routes, string &route_field)
{
    if (!routes.empty()) {

        list<sip_header *>::const_iterator it = routes.begin();

        route_field = c2stlstr((*it)->value);
        ++it;

        for (; it != routes.end(); ++it) {

            route_field += ", " + c2stlstr((*it)->value);
        }
    }
}

void _SipCtrlInterface::terminateConection(const std::string &ip, unsigned short port, unsigned short if_num)
{
    for (unsigned int i = 0; i < nr_trsp_workers; i++) {
        trsp_worker &trsp_worker = *trsp_workers[i];
        if (trsp_worker.remove_connection(ip, port, if_num))
            break;
    }
}

void _SipCtrlInterface::getInfo(AmArg &ret)
{
    ret.assertStruct();
    // if_num
    for (unsigned int i = 0; i < nr_trsp_workers; i++) {
        trsp_worker &trsp_worker = *trsp_workers[i];
        trsp_worker.getInfo(ret);
    }
}

unsigned long long _SipCtrlInterface::getTcpQueueSize()
{
    unsigned long long qsize = 0;
    for (unsigned int i = 0; i < nr_trsp_workers; i++) {
        trsp_worker &trsp_worker = *trsp_workers[i];
        qsize += trsp_worker.getTcpQueueSize();
    }
    return qsize;
}

unsigned long long _SipCtrlInterface::getTlsQueueSize()
{
    unsigned long long qsize = 0;
    for (unsigned int i = 0; i < nr_trsp_workers; i++) {
        trsp_worker &trsp_worker = *trsp_workers[i];
        qsize += trsp_worker.getTlsQueueSize();
    }
    return qsize;
}

unsigned long long _SipCtrlInterface::getWsQueueSize()
{
    unsigned long long qsize = 0;
    for (unsigned int i = 0; i < nr_trsp_workers; i++) {
        trsp_worker &trsp_worker = *trsp_workers[i];
        qsize += trsp_worker.getWsQueueSize();
    }
    return qsize;
}

unsigned long long _SipCtrlInterface::getWssQueueSize()
{
    unsigned long long qsize = 0;
    for (unsigned int i = 0; i < nr_trsp_workers; i++) {
        trsp_worker &trsp_worker = *trsp_workers[i];
        qsize += trsp_worker.getWssQueueSize();
    }
    return qsize;
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-basic-offset: 4
 * End:
 */

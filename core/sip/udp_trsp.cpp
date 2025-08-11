/*
 * $Id: udp_trsp.cpp 1713 2010-03-30 14:11:14Z rco $
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

#define __APPLE_USE_RFC_3542
#include <netinet/in.h>

#include "udp_trsp.h"
#include "ip_util.h"
#include "raw_sender.h"
#include "sip_parser.h"
#include "trans_layer.h"
#include "log.h"
#include "AmUtils.h"
#include "parse_via.h"

#include <sys/param.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netdb.h>

#include <errno.h>
#include <string.h>
#include <AmLcConfig.h>

#include <algorithm>

#if defined IP_RECVDSTADDR
#define DSTADDR_SOCKOPT  IP_RECVDSTADDR
#define DSTADDR_DATASIZE (CMSG_SPACE(sizeof(struct in_addr)))
#define dstaddr(x)       (CMSG_DATA(x))
#elif defined IP_PKTINFO
#define DSTADDR_SOCKOPT  IP_PKTINFO
#define DSTADDR_DATASIZE (CMSG_SPACE(sizeof(struct in_pktinfo)))
#define dstaddr(x)       (&((reinterpret_cast<struct in_pktinfo *>(CMSG_DATA(x)))->ipi_addr))
#else
#error "can't determine v4 socket option (IP_RECVDSTADDR or IP_PKTINFO)"
#endif

// #define RECV_SOCKET_TIMESTAMP

#if defined RECV_SOCKET_TIMESTAMP
#if defined SO_TIMESTAMP
#define TIMESTAMP_DATASIZE (CMSG_SPACE(sizeof(struct timeval)))
#define CMD_MSG_SIZE       (DSTADDR_DATASIZE + TIMESTAMP_DATASIZE)
#else // SO_TIMESTAMP
#error "socket option SO_TIMESTAMP not supported"
#endif // SO_TIMESTAMP
#else  // RECV_SOCKET_TIMESTAMP
#define CMD_MSG_SIZE (DSTADDR_DATASIZE)
#endif // RECV_SOCKET_TIMESTAMP

#if !defined IPV6_RECVPKTINFO
#define DSTADDR6_SOCKOPT IPV6_PKTINFO
#define dstaddr6(x)      (&(((struct in6_pktinfo *)(CMSG_DATA(x)))->ipi6_addr))
#elif defined IPV6_PKTINFO
#define DSTADDR6_SOCKOPT IPV6_RECVPKTINFO
#define dstaddr6(x)      (&((reinterpret_cast<struct in6_pktinfo *>(CMSG_DATA(x)))->ipi6_addr))
#else
#error "cant't determine v6 socket option (IPV6_RECVPKTINFO or IPV6_PKTINFO)"
#endif

#ifndef EPOLLEXCLUSIVE
#define EPOLLEXCLUSIVE (1 << 28)
#endif

/** @see trsp_socket */
int udp_trsp_socket::bind(const string &bind_ip, unsigned short bind_port)
{
    if (sd) {
        WARN("re-binding socket");
        close(sd);
    }

    if (am_inet_pton(bind_ip.c_str(), &addr) == 0) {
        ERROR("am_inet_pton(%s): %s", bind_ip.c_str(), strerror(errno));
        return -1;
    }

    if (((addr.ss_family == AF_INET) && (SAv4(&addr)->sin_addr.s_addr == INADDR_ANY)) ||
        ((addr.ss_family == AF_INET6) && IN6_IS_ADDR_UNSPECIFIED(&SAv6(&addr)->sin6_addr)))
    {
        ERROR("Sorry, we cannot bind to 'ANY' address");
        return -1;
    }

    am_set_port(&addr, bind_port);

    if ((sd = socket(addr.ss_family, SOCK_DGRAM, 0)) == -1) {
        ERROR("socket: %s", strerror(errno));
        return -1;
    }
    SOCKET_LOG("socket(addr.ss_family(%d),SOCK_DGRAM,0) = %d", addr.ss_family, sd);

    if (::bind(sd, (const struct sockaddr *)&addr, SA_len(&addr))) {
        ERROR("bind: %s", strerror(errno));
        close(sd);
        return -1;
    }

    int true_opt = 1;

    if (addr.ss_family == AF_INET) {
        if (setsockopt(sd, IPPROTO_IP, DSTADDR_SOCKOPT, (void *)&true_opt, sizeof(true_opt)) == -1) {
            ERROR("%s", strerror(errno));
            close(sd);
            return -1;
        }
    } else {
        if (setsockopt(sd, IPPROTO_IPV6, DSTADDR6_SOCKOPT, (void *)&true_opt, sizeof(true_opt)) == -1) {
            ERROR("%s", strerror(errno));
            close(sd);
            return -1;
        }
    }

#if defined RECV_SOCKET_TIMESTAMP
    if (setsockopt(sd, SOL_SOCKET, SO_TIMESTAMP, (void *)&true_opt, sizeof(true_opt)) < 0) {
        ERROR("%s", strerror(errno));
        close(sd);
        return -1;
    }
#endif

    actual_port = port = bind_port;
    actual_ip = ip = bind_ip;

    DBG("UDP transport bound to %s/%i", ip.c_str(), port);

    return 0;
}


int udp_trsp_socket::set_recvbuf_size(int rcvbuf_size)
{
    if (rcvbuf_size > 0) {
        DBG("trying to set SIP UDP socket buffer to %d", rcvbuf_size);
        if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (void *)&rcvbuf_size, sizeof(int)) == -1) {
            WARN("could not set SIP UDP socket buffer: '%s'", strerror(errno));
        } else {
            int       set_rcvbuf_size = 0;
            socklen_t optlen          = sizeof(int);
            if (getsockopt(sd, SOL_SOCKET, SO_RCVBUF, &set_rcvbuf_size, &optlen) == -1) {
                WARN("could not read back SIP UDP socket buffer length: '%s'", strerror(errno));
            } else {
                if (set_rcvbuf_size != rcvbuf_size) {
                    WARN("failed to set SIP UDP RCVBUF size"
                         " (wanted %d, got %d)\n",
                         rcvbuf_size, set_rcvbuf_size);
                }
            }
        }
    }

    return 0;
}

int udp_trsp_socket::sendto(const sockaddr_storage *sa, const char *msg, const int msg_len)
{
    int err = ::sendto(sd, msg, msg_len, 0, (const struct sockaddr *)sa, SA_len(sa));

    if (err < 0) {
        char host[NI_MAXHOST] = "";
        ERROR("sendto(%i;%s:%i): %s", sd, am_inet_ntop_sip(sa, host, NI_MAXHOST), am_get_port(sa), strerror(errno));
        return err;
    } else if (err != msg_len) {
        ERROR("sendto: sent %i instead of %i bytes", err, msg_len);
        return -1;
    }

    return 0;
}

int udp_trsp_socket::sendmsg(const sockaddr_storage *sa, const char *msg, const int msg_len)
{
    struct msghdr   hdr;
    struct cmsghdr *cmsg;

    union {
        char cmsg4_buf[CMSG_SPACE(sizeof(struct in_pktinfo))];
        char cmsg6_buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    } cmsg_buf;

    struct iovec msg_iov[1];
    msg_iov[0].iov_base = (void *)msg;
    msg_iov[0].iov_len  = msg_len;

    bzero(&hdr, sizeof(hdr));
    hdr.msg_name    = (void *)sa;
    hdr.msg_namelen = SA_len(sa);
    hdr.msg_iov     = msg_iov;
    hdr.msg_iovlen  = 1;

    bzero(&cmsg_buf, sizeof(cmsg_buf));
    hdr.msg_control    = &cmsg_buf;
    hdr.msg_controllen = sizeof(cmsg_buf);

    cmsg = CMSG_FIRSTHDR(&hdr);
    if (sa->ss_family == AF_INET) {
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type  = IP_PKTINFO;
        cmsg->cmsg_len   = CMSG_LEN(sizeof(struct in_pktinfo));

        struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
        pktinfo->ipi_ifindex       = sys_if_idx;
    } else if (sa->ss_family == AF_INET6) {
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type  = IPV6_PKTINFO;
        cmsg->cmsg_len   = CMSG_LEN(sizeof(struct in6_pktinfo));

        struct in6_pktinfo *pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
        pktinfo->ipi6_ifindex       = sys_if_idx;
    }

    hdr.msg_controllen = cmsg->cmsg_len;

    // bytes_sent = ;
    if (::sendmsg(sd, &hdr, 0) < 0) {
        char host[NI_MAXHOST] = "";
        ERROR("sendmsg(%i;%s:%i): %s", sd, am_inet_ntop_sip(sa, host, NI_MAXHOST), am_get_port(sa), strerror(errno));
        return -1;
    }

    return 0;
}

int udp_trsp_socket::send(const sockaddr_storage *sa, const char *msg, const int msg_len,
                          [[maybe_unused]] unsigned int flags)
{
    if (log_level_raw_msgs >= 0) {
        _LOG(log_level_raw_msgs, "send msg via UDP from %s:%i to %s:%i\n--++--\n%.*s--++--\n", actual_ip.c_str(),
             actual_port, get_addr_str(sa).c_str(), ntohs(((sockaddr_in *)sa)->sin_port), msg_len, msg);
    }

    if (socket_options & use_raw_sockets)
        return raw_sender::send(msg, msg_len, sys_if_idx, &addr, sa, tos_byte);

    if (socket_options & force_outbound_if)
        return sendmsg(sa, msg, msg_len);

    return sendto(sa, msg, msg_len);
}

int udp_trsp_socket::recv()
{
    char    buf[MAX_UDP_MSGLEN];
    u_char  mctrl[DSTADDR_DATASIZE];
    ssize_t buf_len;

    msghdr           msg;
    cmsghdr         *cmsgptr;
    sockaddr_storage from_addr;
    iovec            iov[1];

    iov[0].iov_base = buf;
    iov[0].iov_len  = MAX_UDP_MSGLEN;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name       = &from_addr;
    msg.msg_namelen    = sizeof(sockaddr_storage);
    msg.msg_iov        = iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = mctrl;
    msg.msg_controllen = DSTADDR_DATASIZE;

    buf_len = recvmsg(get_sd(), &msg, MSG_DONTWAIT);
    if (buf_len <= 0) {
        if (!buf_len)
            return 0;
        DBG("recvfrom returned %ld: %s", buf_len, strerror(errno));
        switch (errno) {
        case EBADF:
        case ENOTSOCK:
        case EOPNOTSUPP:
        case EWOULDBLOCK: return 0;
        }
        return errno;
    }

    if (buf_len <= 4) {
        return 0;
    }

    if (buf_len > MAX_UDP_MSGLEN) {
        ERROR("Message was too big (>%d)", MAX_UDP_MSGLEN);
        return 0;
    }

    sockaddr_storage *sa = static_cast<sockaddr_storage *>(msg.msg_name);
    if (!am_get_port(sa)) {
        DBG("Source port is 0: dropping");
        return 0;
    }

    sip_msg *s_msg      = new sip_msg(buf, static_cast<int>(buf_len));
    s_msg->transport_id = sip_transport::UDP;
    memcpy(&s_msg->remote_ip, msg.msg_name, msg.msg_namelen);

    if (trsp_socket::log_level_raw_msgs >= 0) {
        char host[NI_MAXHOST] = "";
        _LOG(trsp_socket::log_level_raw_msgs,
             "vv M [|] u recvd msg via UDP from %s:%i vv\n"
             "--++--\n%.*s--++--\n",
             am_inet_ntop_sip(&s_msg->remote_ip, host, NI_MAXHOST), am_get_port(&s_msg->remote_ip), s_msg->len,
             s_msg->buf);
    }

    s_msg->local_socket = this;
    inc_ref(this);

    for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != nullptr; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
        if (cmsgptr->cmsg_level == IPPROTO_IP && cmsgptr->cmsg_type == DSTADDR_SOCKOPT) {
            s_msg->local_ip.ss_family = AF_INET;
            am_set_port(&s_msg->local_ip, static_cast<short>(get_port()));
            memcpy(&(reinterpret_cast<sockaddr_in *>(&s_msg->local_ip))->sin_addr, dstaddr(cmsgptr), sizeof(in_addr));
        } else if (cmsgptr->cmsg_level == IPPROTO_IPV6 && cmsgptr->cmsg_type == IPV6_PKTINFO) {
            s_msg->local_ip.ss_family = AF_INET6;
            am_set_port(&s_msg->local_ip, static_cast<short>(get_port()));
            memcpy(&(reinterpret_cast<sockaddr_in6 *>(&s_msg->local_ip))->sin6_addr, dstaddr6(cmsgptr),
                   sizeof(in6_addr));
        }
#if defined RECV_SOCKET_TIMESTAMP
        else if (cmsgptr->cmsg_level == SOL_SOCKET && cmsgptr->cmsg_type == SO_TIMESTAMP)
        {
            s_msg->recv_timestamp = *(struct timeval *)CMSG_DATA(cmsgptr);
            DBG("got timestamp %ld.%ld", s_msg->recv_timestamp.tv_sec, s_msg->recv_timestamp.tv_usec);
        }
#endif
    }

#if !defined RECV_SOCKET_TIMESTAMP
    gettimeofday(&s_msg->recv_timestamp, nullptr);
#endif

    // pass message to the parser / transaction layer
    SIP_info *info = AmConfig.sip_ifs[get_if()].proto_info[get_proto_idx()];
    trans_layer::instance()->received_msg(s_msg, info->acls);
    return 1;
}

/** @see trsp_socket */

udp_trsp::udp_trsp()
{
    ev = epoll_create1(0);
}

udp_trsp::~udp_trsp()
{
    if (ev)
        close(ev);
}


/** @see AmThread */
void udp_trsp::run()
{
    if (sockets.empty()) {
        WARN("no interfaces configured for signalling UDP transport");
        return;
    }

    setThreadName("sip-udp-rx");

    DBG("Started SIP server UDP transport");

    int                 ret;
    udp_trsp_socket    *sock;
    bool                running      = true;
    int                 socket_count = static_cast<int>(sockets.size());
    struct epoll_event *events       = new epoll_event[socket_count];

    stop_event.link(ev, true);

    while (running && ev) {
        ret = epoll_wait(ev, events, socket_count, -1);

        if (ret < 0 && errno != EINTR) {
            ERROR("%s: epoll_wait(): %m", __func__);
        }

        if (ret < 1) {
            continue;
        }

        for (int i = 0; i < ret; i++) {

            if (events[i].data.ptr == &stop_event) {
                stop_event.read();
                running = false;
                break;
            }

            sock = static_cast<udp_trsp_socket *>(events[i].data.ptr);

            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
                ERROR("epoll error on socket %s:%d", sock->get_ip(), sock->get_port());

                auto sock_it = std::find(sockets.begin(), sockets.end(), sock);
                if (sock_it != sockets.end()) {
                    sockets.erase(sock_it);
                    if (epoll_ctl(ev, EPOLL_CTL_DEL, sock->get_sd(), nullptr) == -1) {
                        ERROR("epoll_ctl: remove read sock %d error: %d", sock->get_sd(), errno);
                    }
                    dec_ref(sock);
                }
            } else if ((events[i].events & EPOLLIN)) {
                sock->recv();
            }
        }
    }

    for (auto &sock : sockets) {
        DBG("Removed SIP server UDP transport on %s:%d", sock->get_ip(), sock->get_port());
        dec_ref(sock);
    }
    sockets.clear();
    delete[] events;

    DBG("Finished SIP server UDP transport");

    stopped.set(true);
}

/** @see AmThread */
void udp_trsp::on_stop()
{
    stop_event.fire();
    stopped.wait_for();
}

void udp_trsp::add_socket(udp_trsp_socket *sock)
{
    DBG("Added SIP server UDP transport on %s:%d", sock->get_ip(), sock->get_port());
    struct epoll_event event;
    event.events   = EPOLLIN | EPOLLEXCLUSIVE | EPOLLERR;
    event.data.ptr = sock;
    if (epoll_ctl(ev, EPOLL_CTL_ADD, sock->get_sd(), &event) == -1) {
        ERROR("epoll_ctl: add read sock error");
        return;
    }

    sockets.push_back(sock);
    inc_ref(sock);
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-basic-offset: 4
 * End:
 */

/*
 * $Id$
 *
 * Copyright (C) 2010 iptelorg GmbH
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/** raw socket functions.
 *  @file raw_sock.c
 *  @ingroup core
 *  Module: @ref core
 */
/*
 * History:
 * --------
 *  2010-06-07  initial version (from older code) andrei
 */

#ifndef _raw_sock_h
#define _raw_sock_h

#include <sys/socket.h>

int raw_socket(int ip_version, int proto, sockaddr_storage *ip, int iphdr_incl);
int raw_udp_socket(int iphdr_incl);
int raw_udp_socket6(int iphdr_incl);

int raw_udp4_send(int rsock, char *buf, unsigned int len, sockaddr_storage *from, sockaddr_storage *to);

int raw_iphdr_udp4_send(int rsock, const char *buf, unsigned int len, const sockaddr_storage *from,
                        const sockaddr_storage *to, unsigned short mtu, int tos);

int raw_iphdr_udp6_send(int rsock, const char *buf, unsigned int len, const sockaddr_storage *from,
                        const sockaddr_storage *to, unsigned short mtu, int tos);
#endif /* _raw_sock_h */

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
 *  2010-06-15  IP_HDRINCL raw socket support, including on-send
 *               fragmentation (andrei)
 */

#include "ip_util.h"
#include "log.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#ifndef __USE_BSD
#define __USE_BSD  /* on linux use bsd version of iphdr (more portable) */
#endif /* __USE_BSD */
#include <netinet/ip.h>
#include <netinet/ip6.h>
#define __FAVOR_BSD /* on linux use bsd version of udphdr (more portable) */
#include <netinet/udp.h>
#include <netdb.h>

#include "raw_sock.h"

/* likely/unlikely */
#if __GNUC__ >= 3

#define likely(expr)              __builtin_expect(!!(expr), 1)
#define unlikely(expr)            __builtin_expect(!!(expr), 0)

#else /* __GNUC__ */

/* #warning "No compiler optimizations supported try gcc 4.x" */
#define likely(expr) (expr)
#define unlikely(expr) (expr)

#endif /* __GNUC__ */


// macros for converting values in the expected format
// #if OS == "freebsd" || OS == "netbsd" || OS == "darwin"
/* on freebsd and netbsd the ip offset (along with flags) and the
   ip header length must be filled in _host_ bytes order format.
   The same is true for openbsd < 2.1.
*/
#if defined(RAW_IPHDR_IP_HBO)

/** convert the ip offset in the format expected by the kernel. */
#define RAW_IPHDR_IP_OFF(off) (unsigned short)(off)
/** convert the ip total length in the format expected by the kernel. */
#define RAW_IPHDR_IP_LEN(tlen) (unsigned short)(tlen)

#else /* __OS_* */
/* linux, openbsd >= 2.1 a.s.o. */
/** convert the ip offset in the format expected by the kernel. */
#define RAW_IPHDR_IP_OFF(off)  htons((unsigned short)(off))
/** convert the ip total length in the format expected by the kernel. */
#define RAW_IPHDR_IP_LEN(tlen) htons((unsigned short)(tlen))
/** convert the ip flow in the format expected by the kernel. */
#define RAW_IPHDR_IP_FLOW(tflow) htonl((unsigned int)(tflow))

#endif /* __OS_* */

/** create and return a raw socket.
 * @param ip_version - ip version used (e.g. PF_INET, PF_INET6)
 * @param proto - protocol used (e.g. IPPROTO_UDP, IPPROTO_RAW)
 * @param ip - if not null the socket will be bound on this ip.
 * @param iphdr_incl - set to 1 if packets send on this socket include
 *                     a pre-built ip header (some fields, like the checksum
 *                     will still be filled by the kernel, OTOH packet
 *                     fragmentation has to be done in user space).
 * @return socket on success, -1 on error
 */
int raw_socket(int ip_version, int proto, sockaddr_storage* ip, int iphdr_incl)
{
    int sock;
    int t;
    //sockaddr_storage su;

    sock = socket(ip_version, SOCK_RAW, proto);
    SOCKET_LOG("socket(ip_version(%d), SOCK_RAW, proto) = %d",ip_version,sock);
    if (sock==-1)
        goto error;
    /* set socket options */
    if (iphdr_incl) {
        t=1;
        if(ip_version == PF_INET) {
            if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &t, sizeof(t))<0) {
                ERROR("raw_socket: setsockopt(IP_HDRINCL) failed: %s [%d]",
                    strerror(errno), errno);
                goto error;
            }
        } else if(ip_version == PF_INET6) {
#ifndef IPV6_HDRINCL
            ERROR("raw_socket: setsockopt(IPV6_HDRINCL) failed: "
                  "option is not available for kernels before 4.5");
            goto error;
#else
            if (setsockopt(sock, IPPROTO_IPV6, IPV6_HDRINCL, &t, sizeof(t))<0) {
                ERROR("raw_socket: setsockopt(IPV6_HDRINCL) failed: %s [%d]",
                    strerror(errno), errno);
                goto error;
            }
#endif
        }
    } else {
        /* IP_PKTINFO makes no sense if the ip header is included */
        /* using IP_PKTINFO */
        t=1;
#ifdef IP_PKTINFO
        if(ip_version == PF_INET) {
            if (setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &t, sizeof(t))<0) {
                ERROR("raw_socket: setsockopt(IP_PKTINFO) failed: %s [%d]",
                    strerror(errno), errno);
                goto error;
            }
        } else if(ip_version == PF_INET6) {
            if (setsockopt(sock, IPPROTO_IPV6, IPV6_PKTINFO, &t, sizeof(t))<0) {
                ERROR("raw_socket: setsockopt(IPV6_PKTINFO) failed: %s [%d]",
                    strerror(errno), errno);
                goto error;
            }
        }
#elif defined(IP_RECVDSTADDR)
        if(ip_version == PF_INET) {
            if (setsockopt(sock, IPPROTO_IP, IP_RECVDSTADDR, &t, sizeof(t))<0) {
                ERROR("raw_socket: setsockop(IP_RECVDSTADDR) failed: %s [%d]",
                    strerror(errno), errno);
                goto error;
            }
        } else if(ip_version == PF_INET6) {
            if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVDSTADDR, &t, sizeof(t))<0) {
                ERROR("raw_socket: setsockop(IPV6_RECVDSTADDR) failed: %s [%d]",
                    strerror(errno), errno);
                goto error;
            }
        }
#else
#error "no method of getting the destination ip address supported"
#endif /* IP_RECVDSTADDR / IP_PKTINFO */
    }
#if defined (IP_MTU_DISCOVER) && defined (IP_PMTUDISC_DONT)
    t=IP_PMTUDISC_DONT;
    if(ip_version == PF_INET) {
        if(setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &t, sizeof(t)) ==-1) {
            ERROR("raw_socket: setsockopt(IP_MTU_DISCOVER): %s", strerror(errno));
            goto error;
        }
    } else if(ip_version == PF_INET6) {
        if(setsockopt(sock, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &t, sizeof(t)) ==-1) {
            ERROR("raw_socket: setsockopt(IP_MTU_DISCOVER): %s", strerror(errno));
            goto error;
        }
    }
#endif /* IP_MTU_DISCOVER && IP_PMTUDISC_DONT */
    /* FIXME: probe_max_receive_buffer(sock) missing */
    if (ip) {
        if (bind(sock, (sockaddr*)ip, SA_len(ip))==-1) {
            char ip_str[NI_MAXHOST] = "";
            ERROR("raw_socket: bind(%s) failed: %s [%d]",
                am_inet_ntop(ip,ip_str,NI_MAXHOST), strerror(errno), errno);
            goto error;
        }
    }
    return sock;
error:
    if (sock!=-1) close(sock);
    return -1;
}

/** create and return an udp over ipv6  raw socket.
 * @param iphdr_incl - set to 1 if packets send on this socket include
 *                     a pre-built ip header (some fields, like the checksum
 *                     will still be filled by the kernel, OTOH packet
 *                     fragmentation has to be done in user space).
 * @return socket on success, -1 on error
 */
int raw_udp_socket6(int iphdr_incl)
{
    return raw_socket(PF_INET6, IPPROTO_UDP, NULL, iphdr_incl);
}

/** create and return an udp over ipv4  raw socket.
 * @param iphdr_incl - set to 1 if packets send on this socket include
 *                     a pre-built ip header (some fields, like the checksum
 *                     will still be filled by the kernel, OTOH packet
 *                     fragmentation has to be done in user space).
 * @return socket on success, -1 on error
 */
int raw_udp_socket(int iphdr_incl)
{
    return raw_socket(PF_INET, IPPROTO_UDP, NULL, iphdr_incl);
}



/** receives an ipv4 packet using a raw socket.
 * An ipv4 packet is received in buf, using IP_PKTINFO or IP_RECVDSTADDR.
 * from and to are filled (only the ip part the ports are 0 since this
 * function doesn't try to look beyond the IP level).
 * @param sock - raw socket
 * @param buf - detination buffer.
 * @param len - buffer len (should be enough for receiving a packet +
 *               IP header).
 * @param from - result parameter, the IP address part of it will be filled
 *                with the source address and the port with 0.
 * @param to - result parameter, the IP address part of it will be filled
 *                with the destination (local) address and the port with 0.
 * @return packet len or <0 on error: -1 (check errno),
 *        -2 no IP_PKTINFO/IP_RECVDSTADDR found or AF mismatch
 */
// int recvpkt4(int sock, char* buf, int len,
// 	     sockaddr_storage* from, sockaddr_storage* to)
// {
// 	struct iovec iov[1];
// 	struct msghdr rcv_msg;
// 	struct cmsghdr* cmsg;
// #ifdef IP_PKTINFO
// 	struct in_pktinfo* rcv_pktinfo;
// #endif /* IP_PKTINFO */
// 	int n, ret;
// 	char msg_ctrl_buf[1024];

// 	iov[0].iov_base=buf;
// 	iov[0].iov_len=len;
// 	rcv_msg.msg_name=from;
// 	rcv_msg.msg_namelen=sizeof(sockaddr_storage);
// 	rcv_msg.msg_control=msg_ctrl_buf;
// 	rcv_msg.msg_controllen=sizeof(msg_ctrl_buf);
// 	rcv_msg.msg_iov=&iov[0];
// 	rcv_msg.msg_iovlen=1;
// 	ret=-2; /* no PKT_INFO or AF mismatch */
// retry:
// 	n=recvmsg(sock, &rcv_msg, MSG_WAITALL);
// 	if (unlikely(n==-1)){
// 	  if (errno==EINTR)
// 	    goto retry;
// 	  ret=n;
// 	  goto end;
// 	}
// 	/* find the pkt info */
// 	for (cmsg=CMSG_FIRSTHDR(&rcv_msg); cmsg;
// 	     cmsg=CMSG_NXTHDR(&rcv_msg, cmsg)){
// #ifdef IP_PKTINFO
// 	  if ((cmsg->cmsg_level==IPPROTO_IP) &&
// 	      (cmsg->cmsg_type==IP_PKTINFO)) {
// 	    rcv_pktinfo=(struct in_pktinfo*)CMSG_DATA(cmsg);
// 	    to->ss_family=AF_INET;
// 	    memcpy(&SAv4(to)->sin_addr, &rcv_pktinfo->ipi_spec_dst.s_addr
// 		   sizeof(in_addr));
// 	    am_set_port(to,0); /* not known */
// 	    /* interface no. in ipi_ifindex */
// 	    ret=n; /* success */
// 	    break;
// 	  }
// #elif defined (IP_RECVDSTADDR)
// 	  if (likely((cmsg->cmsg_level==IPPROTO_IP) &&
// 		     (cmsg->cmsg_type==IP_RECVDSTADDR))) {
// 	    to->ss_family=AF_INET;
// 	    memcpy(&SAv4(to)->sin_addr, CMSG_DATA(cmsg),
// 		   sizeof(in_addr));
// 	    am_set_port(to,0); /* not known */
// 	    ret=n; /* success */
// 	    break;
// 	  }
// #else
// #error "no method of getting the destination ip address supported"
// #endif /* IP_PKTINFO / IP_RECVDSTADDR */
// 	}
//  end:
// 	return ret;
// }



/* receive an ipv4 udp packet over a raw socket.
 * The packet is copied in *buf and *buf is advanced to point to the
 * payload.  Fills from and to.
 * @param rsock - raw socket
 * @param buf - the packet will be written to where *buf points intially and
 *              then *buf will be advanced to point to the udp payload.
 * @param len - buffer length (should be enough to hold at least the
 *               ip and udp headers + 1 byte).
 * @param from - result parameter, filled with source address and port of the
 *               packet.
 * @param from - result parameter, filled with destination (local) address and
 *               port of the packet.
 * @param rf   - filter used to decide whether or not the packet is
 *                accepted/processed. If null, all the packets are accepted.
 * @return packet len or  <0 on error (-1 and -2 on recv error @see recvpkt4,
 *         -3 if the headers are invalid and -4 if the packet doesn't
 *         match the  filter).
 */
// int raw_udp4_recv(int rsock, char** buf, int len,
// 		  sockaddr_storage* from, sockaddr_storage* to)
// {
// 	int n;
// 	unsigned short dst_port;
// 	unsigned short src_port;
// 	//struct ip_addr dst_ip;
// 	char* end;
// 	char* udph_start;
// 	char* udp_payload;
// 	struct ip iph;
// 	struct udphdr udph;
// 	unsigned short udp_len;

// 	n=recvpkt4(rsock, *buf, len, from, to);
// 	if (unlikely(n<0)) goto error;
	
// 	end=*buf+n;
// 	if (unlikely(n<(sizeof(struct ip)+sizeof(struct udphdr)))) {
// 		n=-3;
// 		goto error;
// 	}
	
// 	/* FIXME: if initial buffer is aligned, one could skip the memcpy
// 	   and directly cast ip and udphdr pointer to the memory */
// 	memcpy(&iph, *buf, sizeof(struct ip));
// 	udph_start=*buf+iph.ip_hl*4;
// 	udp_payload=udph_start+sizeof(struct udphdr);
// 	if (unlikely(udp_payload>end)){
// 		n=-3;
// 		goto error;
// 	}
// 	memcpy(&udph, udph_start, sizeof(struct udphdr));
// 	udp_len=ntohs(udph.uh_ulen);
// 	if (unlikely((udph_start+udp_len)!=end)){
// 		if ((udph_start+udp_len)>end){
// 			n=-3;
// 			goto error;
// 		}else{
// 			ERROR("udp length too small: %d/%d",
// 			      (int)udp_len, (int)(end-udph_start));
// 			n=-3;
// 			goto error;
// 		}
// 	}
// 	/* advance buf */
// 	*buf=udp_payload;
// 	n=(int)(end-*buf);
// 	/* fill ip from the packet (needed if no PKT_INFO is used) */
// 	dst_ip.af=AF_INET;
// 	dst_ip.len=4;
// 	dst_ip.u.addr32[0]=iph.ip_dst.s_addr;
// 	/* fill dst_port */
// 	dst_port=ntohs(udph.uh_dport);
// 	ip_addr2su(to, &dst_ip, dst_port);
// 	/* fill src_port */
// 	src_port=ntohs(udph.uh_sport);
// 	su_setport(from, src_port);
// 	// if (likely(rf)) {
// 	// 	su2ip_addr(&dst_ip, to);
// 	// 	if ( (dst_port && rf->port1 && ((dst_port<rf->port1) ||
// 	// 					(dst_port>rf->port2)) ) ||
// 	// 		(matchnet(&dst_ip, &rf->dst)!=1) ){
// 	// 		/* no match */
// 	// 		n=-4;
// 	// 		goto error;
// 	// 	}
// 	// }
// error:
// 	return n;
// }

/** udp checksum helper: compute the pseudo-header 16-bit "sum".
 * Computes the partial checksum (no complement) of the pseudo-header.
 * It is meant to be used by udpv4_chksum().
 * @param uh - filled udp header
 * @param src - source ip address in network byte order.
 * @param dst - destination ip address in network byte order.
 * @param length - payload length (not including the udp header),
 *                 in _host_ order.
 * @return the partial checksum in host order
 */
inline unsigned short udpv4_vhdr_sum(struct udphdr* uh,
                                     struct in_addr* src,
                                     struct in_addr* dst,
                                     unsigned short)
{
    unsigned sum;

    /* pseudo header */
    sum=(src->s_addr>>16)+(src->s_addr&0xffff)+
        (dst->s_addr>>16)+(dst->s_addr&0xffff)+
        htons(IPPROTO_UDP)+(uh->uh_ulen);
    /* udp header */
    sum+=(uh->uh_dport)+(uh->uh_sport)+(uh->uh_ulen) + 0 /*chksum*/;
    /* fold it */
    sum=(sum>>16)+(sum&0xffff);
    sum+=(sum>>16);
    /* no complement */
    return ntohs((unsigned short) sum);
}

/** compute the udp over ipv4 checksum.
 * @param u - filled udp header (except checksum).
 * @param src - source ip v4 address, in _network_ byte order.
 * @param dst - destination ip v4 address, int _network_ byte order.
 * @param data - pointer to the udp payload.
 * @param length - payload length, not including the udp header and in
 *                 _host_ order. The length mist be <= 0xffff - 8
 *                 (to allow space for the udp header).
 * @return the checksum in _host_ order */
inline static unsigned short udpv4_chksum(struct udphdr* u,
					  struct in_addr* src,
					  struct in_addr* dst,
					  unsigned char* data,
					  unsigned short length)
{
    unsigned sum;
    unsigned char* end;
    sum=udpv4_vhdr_sum(u, src, dst, length);
    end=data+(length&(~0x1)); /* make sure it's even */
    /* TODO: 16 & 32 bit aligned version */
    /* not aligned */
    for(;data<end;data+=2) {
        sum+=((data[0]<<8)+data[1]);
    }
    if (length&0x1)
        sum+=((*data)<<8);

    /* fold it */
    sum=(sum>>16)+(sum&0xffff);
    sum+=(sum>>16);
    return (unsigned short)~sum;
}

static unsigned short udpv6_chksum(struct udphdr* u,
					  struct in6_addr* src,
					  struct in6_addr* dst,
					  unsigned char* data,
					  unsigned short length)
{
    unsigned sum = 0;
    struct pseudo_header {
    /* We use a union here to avoid aliasing issues with gcc -O2 */
        union {
            struct {
                struct in6_addr src_ip;
                struct in6_addr dst_ip;
                uint32_t length;
                uint8_t zero[3];
                uint8_t next_header;
            } head;
            uint32_t words[10];
        } headu;
#define header_src headu.head.src_ip
#define header_dst headu.head.dst_ip
#define header_len headu.head.length
#define header_zero headu.head.zero
#define header_proto headu.head.next_header
    };

    struct pseudo_header header;
    header.header_src = *src;
    header.header_dst = *dst;
    header.header_proto = IPPROTO_UDP;
    header.header_len = htonl(length + sizeof(struct udphdr));
    memset(header.header_zero, 0, sizeof(header.header_zero));
    uint32_t count = sizeof(header);
    uint16_t* data_ = (uint16_t*)&header;
    while (count > 1) {
        sum += *(data_++);
        count -= 2;
    }

    /*udp header*/
    sum += u->uh_sport + u->uh_dport + u->uh_ulen;

    /*data*/
    count = length;
    data_ = (uint16_t*)data;
    while (count > 1) {
        sum += *(data_++);
        count -= 2;
    }
    if (length&0x1)
        sum+=htons((*data_)<<8);

    /* fold it */
    sum=(sum>>16)+(sum&0xffff);
    sum+=(sum>>16);
    return htons((unsigned short)~sum);
}

/** fill in an udp header.
 * @param u - udp header that will be filled.
 * @param from - source ip v4 address and port.
 * @param to -   destination ip v4 address and port.
 * @param buf - pointer to the payload.
 * @param len - payload length (not including the udp header).
 * @param do_chk - if set the udp checksum will be computed, else it will
 *                 be set to 0.
 * @return 0 on success, < 0 on error.
 */
static int mk_udp_hdr(struct udphdr* u,
                      const sockaddr_storage* from,
                      const sockaddr_storage* to,
                      unsigned char* buf, int len,
                      int do_chk)
{
    if(from->ss_family == AF_INET) {
        struct sockaddr_in *from_v4 = (sockaddr_in*)from;
        struct sockaddr_in *to_v4 = (sockaddr_in*)to;

        u->uh_ulen = htons((unsigned short)len+sizeof(struct udphdr));
        u->uh_sport = ((sockaddr_in*)from)->sin_port;
        u->uh_dport = ((sockaddr_in*)to)->sin_port;

        if (do_chk) {
            u->uh_sum=htons(udpv4_chksum(u, &from_v4->sin_addr,
                                         &to_v4->sin_addr, buf, len));
        } else {
            u->uh_sum=0; /* no checksum */
        }

    } else if(from->ss_family == AF_INET6) {
        struct sockaddr_in6 *from_v6 = (sockaddr_in6*)from;
        struct sockaddr_in6 *to_v6 = (sockaddr_in6*)to;

        u->uh_ulen = htons((unsigned short)len+sizeof(struct udphdr));
        u->uh_sport = ((sockaddr_in6*)from)->sin6_port;
        u->uh_dport = ((sockaddr_in6*)to)->sin6_port;
        if (do_chk) {
             u->uh_sum=htons(udpv6_chksum(u, &from_v6->sin6_addr,
                                          &to_v6->sin6_addr, buf, len));
        } else {
          u->uh_sum=0; /* no checksum */
        }
    }
    return 0;
}



/** fill in an ip header.
 * Note: the checksum is _not_ computed.
 * WARNING: The ip header length and offset might be filled in
 * _host_ byte order or network byte order (depending on the OS, for example
 *  freebsd needs host byte order for raw sockets with IPHDR_INC, while
 *  linux needs network byte order).
 * @param iph - ip header that will be filled.
 * @param from - source ip v4 address (network byte order).
 * @param to -   destination ip v4 address (network byte order).
 * @param payload len - payload length (not including the ip header).
 * @param proto - protocol.
 * @return 0 on success, < 0 on error.
 */
inline static int mk_ip_hdr(struct ip* iph, struct in_addr* from,
                            struct in_addr* to, int payload_len,
                            unsigned char proto, int tos)
{
    iph->ip_hl = sizeof(struct ip)/4;
    iph->ip_v = 4;
    iph->ip_tos = tos;
    /* on freebsd ip_len _must_ be in _host_ byte order instead
       of network byte order. On linux the length is ignored (it's filled
       automatically every time). */
    iph->ip_len = RAW_IPHDR_IP_LEN(payload_len + sizeof(struct ip));
    iph->ip_id = 0; /* 0 => will be filled automatically by the kernel */
    iph->ip_off = 0; /* frag.: first 3 bits=flags=0, last 13 bits=offset */
    iph->ip_ttl = 64;//cfg_get(core, core_cfg, udp4_raw_ttl);
    iph->ip_p = proto;
    iph->ip_src = *from;
    iph->ip_dst = *to;
    iph->ip_sum = 0;

    return 0;
}

inline static int mk_ip6_hdr(struct ip6_hdr* iph, struct in6_addr* from,
                             struct in6_addr* to, int payload_len,
                             unsigned char proto, int tos)
{
    iph->ip6_flow = RAW_IPHDR_IP_FLOW((6<<28)|(tos<<20));
    iph->ip6_plen = RAW_IPHDR_IP_LEN(payload_len);
    iph->ip6_nxt = proto;
    iph->ip6_hlim = 64;
    iph->ip6_src = *from;
    iph->ip6_dst = *to;
    return 0;
}

inline static int mk_frag_hdr(struct ip6_frag* frag, unsigned char proto, unsigned short frag_offs, bool last_frag, unsigned int id)
{
    frag->ip6f_nxt = proto;
    frag->ip6f_reserved = 0;
    frag->ip6f_offlg = (frag_offs<<3) | (last_frag ? 0 : 1);
    frag->ip6f_ident = id;
    return 0;
}

static int raw_iphdr_nonfrag_udp6_send(int rsock, const char* buf, unsigned int len,
                                       const sockaddr_storage* from,
                                       const sockaddr_storage* to, int tos)
{
    struct ip6_udp_hdr {
        struct ip6_hdr ip;
        struct udphdr udp;
    } hdr;
    unsigned int totlen = len + sizeof(hdr);
    if (unlikely(totlen) > 65535)
        return -2;

    if(SAv4(to)->sin_family!=AF_INET6) {
        static int complained = 0;
        if(!complained++) {
            ERROR("raw_iphdr_udp6_send: wrong address family %i for destination address",
                SAv4(to)->sin_family);
            log_stacktrace(L_ERR);
        }
    }

    if(SAv4(from)->sin_family!=AF_INET6) {
        static int complained = 0;
        if(!complained++){
            ERROR("raw_iphdr_udp6_send: wrong address family %i for source address",
                SAv4(from)->sin_family);
            log_stacktrace(L_ERR);
        }
    }

    /* prepare the udp & ip6 headers */
    mk_udp_hdr(&hdr.udp, from, to, (unsigned char*)buf, len, 1);
    mk_ip6_hdr(&hdr.ip, &SAv6(from)->sin6_addr, &SAv6(to)->sin6_addr,
          len + sizeof(hdr.udp), IPPROTO_UDP, tos);

    struct iovec iov[2];
    iov[0].iov_base=(char*)&hdr;
    iov[0].iov_len=sizeof(hdr);
    iov[1].iov_base=(void*)buf;
    iov[1].iov_len=len;

    char msg_ctrl_snd_buf[1024] = {0};
    struct msghdr snd_msg;
    memset(&snd_msg, 0, sizeof(snd_msg));
    sockaddr_in6 to_addr;
    memcpy(&to_addr, to, sizeof(sockaddr_in6));
    to_addr.sin6_port = 0;
    snd_msg.msg_name=&to_addr;
    snd_msg.msg_namelen=SA_len(to);
    snd_msg.msg_iov=&iov[0];
    snd_msg.msg_iovlen=2;
    snd_msg.msg_control = msg_ctrl_snd_buf;
    snd_msg.msg_controllen = sizeof(msg_ctrl_snd_buf);
    /* init pktinfo cmsg */
    struct cmsghdr* cmsg;
    cmsg=CMSG_FIRSTHDR(&snd_msg);
    cmsg->cmsg_level=IPPROTO_IPV6;
    #ifdef IPV6_PKTINFO
    struct in6_pktinfo* snd_pktinfo;
    cmsg->cmsg_type=IPV6_PKTINFO;
    cmsg->cmsg_len=CMSG_LEN(sizeof(struct in6_pktinfo));
    snd_pktinfo=(struct in6_pktinfo*)CMSG_DATA(cmsg);
    snd_pktinfo->ipi6_ifindex=0;
    snd_pktinfo->ipi6_addr=SAv6(from)->sin6_addr;
    #elif defined (IP_SENDSRCADDR)
    cmsg->cmsg_type=IP_SENDSRCADDR;
    cmsg->cmsg_len=CMSG_LEN(sizeof(struct in6_addr));
    #else
    #error "no method of setting the source ip supported"
    #endif /* IP_PKTINFO / IP_SENDSRCADDR */
    snd_msg.msg_controllen=cmsg->cmsg_len;
    snd_msg.msg_flags=0;

    return sendmsg(rsock, &snd_msg, 0);
}

static int raw_iphdr_frag_udp6_send(int rsock, const char* buf, unsigned int len,
                                    const sockaddr_storage* from,
                                    const sockaddr_storage* to,
                                    unsigned short mtu, int tos)
{
    struct ip6_udp_hdr {
        struct ip6_hdr ip;
        struct ip6_frag frag;
        struct udphdr udp;
    } hdr;
    unsigned int totlen = len + sizeof(hdr);
    if (unlikely(totlen) > 65535)
        return -2;

    if(SAv4(to)->sin_family!=AF_INET6) {
        static int complained = 0;
        if(!complained++) {
            ERROR("raw_iphdr_udp6_send: wrong address family %i for destination address",
                SAv4(to)->sin_family);
            log_stacktrace(L_ERR);
        }
    }

    if(SAv4(from)->sin_family!=AF_INET6) {
        static int complained = 0;
        if(!complained++) {
            ERROR("raw_iphdr_udp6_send: wrong address family %i for source address",
                SAv4(from)->sin_family);
            log_stacktrace(L_ERR);
        }
    }

    /* a fragment offset must be a multiple of 8 => its size must
        also be a multiple of 8, except for the last fragment */
    unsigned int ip_frag_size = (mtu - sizeof(hdr.ip)) & (~7); /* fragment size */
    unsigned int last_frag_extra = (mtu - sizeof(hdr.ip)) & 7; /* extra bytes possible in the last frag */
    unsigned int ip_payload = len + sizeof(hdr.udp) + sizeof(struct ip6_frag);
    int frg_no = ip_payload / ip_frag_size + ((ip_payload % ip_frag_size) > last_frag_extra);
    unsigned int last_frag_offs = (frg_no - 1) * ip_frag_size;
    unsigned int id = rand();
    void* last_frag_start = (void*)(buf + last_frag_offs - sizeof(hdr.udp));

    /* prepare the fragment && udp & ip6 headers */
    mk_udp_hdr(&hdr.udp, from, to, (unsigned char*)buf, len, 1);
    mk_frag_hdr(&hdr.frag, IPPROTO_UDP, 0, false, id);
    mk_ip6_hdr(&hdr.ip, &SAv6(from)->sin6_addr, &SAv6(to)->sin6_addr,
               ip_frag_size, IPPROTO_FRAGMENT, tos);

    struct iovec iov[2];
    /* first fragment */
    iov[0].iov_base=(char*)&hdr;
    iov[0].iov_len=sizeof(hdr);
    iov[1].iov_base=(void*)buf;
    iov[1].iov_len= ip_frag_size-sizeof(hdr.udp)-sizeof(hdr.frag);

    struct msghdr snd_msg;
    char msg_ctrl_snd_buf[1024];
    memset(&snd_msg, 0, sizeof(snd_msg));
    sockaddr_in6 to_addr;
    memcpy(&to_addr, to, sizeof(sockaddr_in6));
    to_addr.sin6_port = 0;
    snd_msg.msg_name=&to_addr;
    snd_msg.msg_name=SAv6(to);
    snd_msg.msg_namelen=SA_len(to);
    snd_msg.msg_iov=&iov[0];
    snd_msg.msg_iovlen=2;
    snd_msg.msg_flags=0;
    snd_msg.msg_control = msg_ctrl_snd_buf;
    snd_msg.msg_controllen = sizeof(msg_ctrl_snd_buf);

    int bytes_sent;
    int ret;

    ret = sendmsg(rsock, &snd_msg, 0);
    if (unlikely(ret < 0))
        return ret;
    bytes_sent = ret;

    /* all the other fragments, include only the ip header and fragnet headers */
    iov[0].iov_len = sizeof(hdr.ip) + sizeof(hdr.frag);
    iov[1].iov_base =  (char*)iov[1].iov_base + iov[1].iov_len;
    /* fragments between the first and the last */
    while(unlikely(iov[1].iov_base < last_frag_start)) {
        unsigned short offset = RAW_IPHDR_IP_OFF((unsigned short)(((char*)iov[1].iov_base - (char*)buf + sizeof(hdr.udp))/8));
        mk_frag_hdr(&hdr.frag, IPPROTO_UDP, offset, false, id);
        mk_ip6_hdr(&hdr.ip, &SAv6(from)->sin6_addr, &SAv6(to)->sin6_addr,
                    ip_frag_size, IPPROTO_FRAGMENT, tos);
        ret=sendmsg(rsock, &snd_msg, 0);
        if (unlikely(ret < 0))
          return ret;
        bytes_sent+=ret;
        iov[1].iov_base =  (char*)iov[1].iov_base + iov[1].iov_len;
    }
    /* last fragment */
    iov[1].iov_len = buf + len - (char*)iov[1].iov_base;
    unsigned short offset = RAW_IPHDR_IP_OFF((unsigned short)(((char*)iov[1].iov_base - (char*)buf + sizeof(hdr.udp))/8));
    mk_frag_hdr(&hdr.frag, IPPROTO_UDP, offset, true, id);
    mk_ip6_hdr(&hdr.ip, &SAv6(from)->sin6_addr, &SAv6(to)->sin6_addr,
                    iov[1].iov_len, IPPROTO_FRAGMENT, tos);
    ret=sendmsg(rsock, &snd_msg, 0);
    if (unlikely(ret < 0))
        return ret;
    ret+=bytes_sent;
    return ret;
}

/** send an udp packet over a non-ip_hdrincl raw socket.
 * @param rsock - raw socket
 * @param buf - data
 * @param len - data len
 * @param from - source address:port (_must_ be non-null, but the ip address
 *                can be 0, in which case it will be filled by the kernel).
 * @param to - destination address:port
 * @return  <0 on error (errno set too), number of bytes sent on success
 *          (including the udp header => on success len + udpheader size).
 */
int raw_udp4_send(int rsock, char* buf, unsigned int len,
                  sockaddr_storage* from, sockaddr_storage* to)
{
    struct msghdr snd_msg;
    struct cmsghdr* cmsg;
    #ifdef IP_PKTINFO
    struct in_pktinfo* snd_pktinfo;
    #endif /* IP_PKTINFO */
    struct iovec iov[2];
    struct udphdr udp_hdr;
    char msg_ctrl_snd_buf[1024];
    int ret;

    memset(&snd_msg, 0, sizeof(snd_msg));
    snd_msg.msg_name=SAv4(to);
    snd_msg.msg_namelen=SA_len(to);
    snd_msg.msg_iov=&iov[0];
    /* prepare udp header */
    mk_udp_hdr(&udp_hdr, from, to, (unsigned char*)buf, len, 1);
    iov[0].iov_base=(char*)&udp_hdr;
    iov[0].iov_len=sizeof(udp_hdr);
    iov[1].iov_base=buf;
    iov[1].iov_len=len;
    snd_msg.msg_iovlen=2;
    snd_msg.msg_control=msg_ctrl_snd_buf;
    snd_msg.msg_controllen=sizeof(msg_ctrl_snd_buf);
    /* init pktinfo cmsg */
    cmsg=CMSG_FIRSTHDR(&snd_msg);
    cmsg->cmsg_level=IPPROTO_IP;
    #ifdef IP_PKTINFO
    cmsg->cmsg_type=IP_PKTINFO;
    cmsg->cmsg_len=CMSG_LEN(sizeof(struct in_pktinfo));
    snd_pktinfo=(struct in_pktinfo*)CMSG_DATA(cmsg);
    snd_pktinfo->ipi_ifindex=0;
    snd_pktinfo->ipi_spec_dst.s_addr=SAv4(&from)->sin_addr.s_addr;
    #elif defined (IP_SENDSRCADDR)
    cmsg->cmsg_type=IP_SENDSRCADDR;
    cmsg->cmsg_len=CMSG_LEN(sizeof(struct in_addr));
    memcpy(CMSG_DATA(cmsg), &SAv4(&from)->sin_addr.s_addr,
           sizeof(struct in_addr));
    #else
    #error "no method of setting the source ip supported"
    #endif /* IP_PKTINFO / IP_SENDSRCADDR */
    snd_msg.msg_controllen=cmsg->cmsg_len;
    snd_msg.msg_flags=0;
    ret=sendmsg(rsock, &snd_msg, 0);
    return ret;
}



/** send an udp packet over an IP_HDRINCL raw socket.
 * If needed, send several fragments.
 * @param rsock - raw socket
 * @param buf - data
 * @param len - data len
 * @param from - source address:port (_must_ be non-null, but the ip address
 *                can be 0, in which case it will be filled by the kernel).
 * @param to - destination address:port
 * @param mtu - maximum datagram size (including the ip header, excluding
 *              link layer headers). Minimum allowed size is 28
 *               (sizeof(ip_header + udp_header)). If mtu is lower, it will
 *               be ignored (the packet will be sent un-fragmented).
 *              0 can be used to disable fragmentation.
 * @return  <0 on error (-2: datagram too big, -1: check errno),
 *          number of bytes sent on success
 *          (including the ip & udp headers =>
 *               on success len + udpheader + ipheader size).
 */
int raw_iphdr_udp4_send(int rsock, const char* buf, unsigned int len,
                        const sockaddr_storage* from,
                        const sockaddr_storage* to,
                        unsigned short mtu, int tos)
{
    struct msghdr snd_msg;
    struct iovec iov[2];
    struct ip_udp_hdr {
        struct ip ip;
        struct udphdr udp;
    } hdr;
    unsigned int totlen;
    #ifndef RAW_IPHDR_INC_AUTO_FRAG
    unsigned int ip_frag_size; /* fragment size */
    unsigned int last_frag_extra; /* extra bytes possible in the last frag */
    unsigned int ip_payload;
    unsigned int last_frag_offs;
    void* last_frag_start;
    int frg_no;
    #endif /* RAW_IPHDR_INC_AUTO_FRAG */
    int ret;

    if(SAv4(to)->sin_family!=AF_INET){
        static int complained = 0;
        if(!complained++){
            ERROR("raw_iphdr_udp4_send: wrong address family %i for destination address",
                SAv4(to)->sin_family);
            log_stacktrace(L_ERR);
        }
    }

    if(SAv4(from)->sin_family!=AF_INET){
        static int complained = 0;
        if(!complained++){
            ERROR("raw_iphdr_udp4_send: wrong address family %i for source address",
                SAv4(from)->sin_family);
            log_stacktrace(L_ERR);
        }
    }

    totlen = len + sizeof(hdr);
    if (unlikely(totlen) > 65535)
        return -2;
    memset(&snd_msg, 0, sizeof(snd_msg));
    snd_msg.msg_name=SAv4(to);
    snd_msg.msg_namelen=SA_len(to);
    snd_msg.msg_iov=&iov[0];
    /* prepare the udp & ip headers */
    mk_udp_hdr(&hdr.udp, from, to, (unsigned char*)buf, len, 1);
    mk_ip_hdr(&hdr.ip, &SAv4(from)->sin_addr, &SAv4(to)->sin_addr,
          len + sizeof(hdr.udp), IPPROTO_UDP, tos);
    iov[0].iov_base=(char*)&hdr;
    iov[0].iov_len=sizeof(hdr);
    snd_msg.msg_iovlen=2;
    snd_msg.msg_control=0;
    snd_msg.msg_controllen=0;
    snd_msg.msg_flags=0;
    /* this part changes for different fragments */
    /* packets are fragmented if mtu has a valid value (at least an
       IP header + UDP header fit in it) and if the total length is greater
       then the mtu */
#ifndef RAW_IPHDR_INC_AUTO_FRAG
    if (likely(totlen <= mtu || mtu <= sizeof(hdr))) {
#endif /* RAW_IPHDR_INC_AUTO_FRAG */
        iov[1].iov_base=(void*)buf;
        iov[1].iov_len=len;
        ret=sendmsg(rsock, &snd_msg, 0);
#ifndef RAW_IPHDR_INC_AUTO_FRAG
    } else {
        int bytes_sent;
        ip_payload = len + sizeof(hdr.udp);
        /* a fragment offset must be a multiple of 8 => its size must
         also be a multiple of 8, except for the last fragment */
        ip_frag_size = (mtu -sizeof(hdr.ip)) & (~7);
        last_frag_extra = (mtu - sizeof(hdr.ip)) & 7; /* rest */
        frg_no = ip_payload / ip_frag_size +
                 ((ip_payload % ip_frag_size) > last_frag_extra);
        /*ip_last_frag_size = ip_payload % frag_size +
        ((ip_payload % frag_size) <= last_frag_extra) *
        ip_frag_size; */
        last_frag_offs = (frg_no - 1) * ip_frag_size;
        /* if we are here mtu => sizeof(ip_h+udp_h) && payload > mtu
         => last_frag_offs >= sizeof(hdr.udp) */
        last_frag_start = (void*)(buf + last_frag_offs - sizeof(hdr.udp));
        /* random id, should be != 0
         (if 0 the kernel will fill it) */
        hdr.ip.ip_id = 0; //fastrand_max(65534) + 1;
        /* send the first fragment */
        iov[1].iov_base=(void*)buf;
        /* ip_frag_size >= sizeof(hdr.udp) because we are here only
         if mtu >= sizeof(hdr.ip) + sizeof(hdr.udp) */
        iov[1].iov_len=ip_frag_size - sizeof(hdr.udp);
        hdr.ip.ip_len = RAW_IPHDR_IP_LEN(ip_frag_size + sizeof(hdr.ip));
        hdr.ip.ip_off = RAW_IPHDR_IP_OFF(0x2000); /* set MF */

        ret=sendmsg(rsock, &snd_msg, 0);
        if (unlikely(ret < 0))
            goto end;

        bytes_sent = ret;
        /* all the other fragments, include only the ip header */
        iov[0].iov_len = sizeof(hdr.ip);
        iov[1].iov_base =  (char*)iov[1].iov_base + iov[1].iov_len;
        /* fragments between the first and the last */

        while(unlikely(iov[1].iov_base < last_frag_start)) {
            iov[1].iov_len = ip_frag_size;
            hdr.ip.ip_len = RAW_IPHDR_IP_LEN(iov[1].iov_len + sizeof(hdr.ip));
            /* set MF  */
            hdr.ip.ip_off =
                RAW_IPHDR_IP_OFF((unsigned short)
                    (((char*)iov[1].iov_base
                    - (char*)buf + sizeof(hdr.udp))
                    / 8) | 0x2000 );

            ret=sendmsg(rsock, &snd_msg, 0);
            if (unlikely(ret < 0))
                goto end;

            bytes_sent+=ret;
            iov[1].iov_base =  (char*)iov[1].iov_base + iov[1].iov_len;
        }

        /* last fragment */
        iov[1].iov_len = buf + len - (char*)iov[1].iov_base;
        hdr.ip.ip_len = RAW_IPHDR_IP_LEN(iov[1].iov_len + sizeof(hdr.ip));

        /* don't set MF (last fragment) */
        hdr.ip.ip_off = RAW_IPHDR_IP_OFF((unsigned short)
                       (((char*)iov[1].iov_base
                         - (char*)buf + sizeof(hdr.udp))
                        / 8) );

        ret=sendmsg(rsock, &snd_msg, 0);
        if (unlikely(ret < 0))
            goto end;

        ret+=bytes_sent;
    }
end:
#endif /* RAW_IPHDR_INC_AUTO_FRAG */
    return ret;
}

/** send an udp packet over an IP_HDRINCL raw socket.
 * If needed, send several fragments.
 * @param rsock - raw socket
 * @param buf - data
 * @param len - data len
 * @param from - source address:port (_must_ be non-null, but the ip address
 *                can be 0, in which case it will be filled by the kernel).
 * @param to - destination address:port
 * @param mtu - maximum datagram size (including the ip header, excluding
 *              link layer headers). Minimum allowed size is 28
 *               (sizeof(ip_header + udp_header)). If mtu is lower, it will
 *               be ignored (the packet will be sent un-fragmented).
 *              0 can be used to disable fragmentation.
 * @return  <0 on error (-2: datagram too big, -1: check errno),
 *          number of bytes sent on success
 *          (including the ip & udp headers =>
 *               on success len + udpheader + ipheader size).
 */
int raw_iphdr_udp6_send(int rsock, const char* buf, unsigned int len,
                        const sockaddr_storage* from,
                        const sockaddr_storage* to,
                        unsigned short mtu, int tos)
{
    /* this part changes for different fragments */
    /* packets are fragmented if mtu has a valid value (at least an
       IP header + UDP header fit in it) and if the total length is greater
       then the mtu */
    unsigned int headlen = sizeof(struct ip6_hdr) + sizeof(struct udphdr);
    unsigned int totlen = len + headlen;
#ifndef RAW_IPHDR_INC_AUTO_FRAG
    if (likely(totlen <= mtu || mtu <= headlen)) {
#endif /* RAW_IPHDR_INC_AUTO_FRAG */
        return raw_iphdr_nonfrag_udp6_send(rsock, buf, len, from, to, tos);
#ifndef RAW_IPHDR_INC_AUTO_FRAG
    } else {
        return raw_iphdr_frag_udp6_send(rsock, buf, len, from, to, mtu, tos);
    }
#endif /* RAW_IPHDR_INC_AUTO_FRAG */
}

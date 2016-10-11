#include "msg_sensor.h"

#include "AmUtils.h"
#include "sip/raw_sock.h"
#include "ip_util.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <netinet/ether.h>
#ifndef __USE_BSD
#define __USE_BSD  /* on linux use bsd version of iphdr (more portable) */
#endif /* __USE_BSD */
#include <netinet/ip.h>
#define __FAVOR_BSD /* on linux use bsd version of udphdr (more portable) */
#include <netinet/udp.h>
#include <netdb.h>


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

#endif /* __OS_* */

#define DEFAULT_IPIP_TTL 64

/* most of helper function is from core/sip/raw_sock.cpp */


static uint16_t ipv4_chksum(uint32_t sum)
{
  while (sum >> 16) { sum = (sum >> 16) + (sum & 0xFFFF); }

  uint16_t res = sum;
  res = ~res;
  if (res == 0) res = ~res;

  return res;
}

static uint32_t sum(const void *_data, unsigned _len)
{
  const uint16_t *data = (const uint16_t *)_data;
  unsigned len = _len >> 1;

  uint32_t r = 0;
  for (unsigned i = 0; i < len; i++) r += data[i];
  if (_len & 1) r += (unsigned)((const char*)_data)[_len - 1];

  return r;
}

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
					 unsigned short length)
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
		for(;data<end;data+=2){
			sum+=((data[0]<<8)+data[1]);
		}
		if (length&0x1)
			sum+=((*data)<<8);

	/* fold it */
	sum=(sum>>16)+(sum&0xffff);
	sum+=(sum>>16);
	return (unsigned short)~sum;
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
inline static int mk_udp_hdr(struct udphdr* u,
				 const sockaddr_storage* from,
				 const sockaddr_storage* to,
				 unsigned char* buf, int len,
				 int do_chk)
{
  struct sockaddr_in *from_v4 = (sockaddr_in*)from;
  struct sockaddr_in *to_v4 = (sockaddr_in*)to;

  u->uh_ulen = htons((unsigned short)len+sizeof(struct udphdr));
  u->uh_sport = ((sockaddr_in*)from)->sin_port;
  u->uh_dport = ((sockaddr_in*)to)->sin_port;
  if (do_chk)
	u->uh_sum=htons(udpv4_chksum(u, &from_v4->sin_addr,
				 &to_v4->sin_addr, buf, len));
  else
	u->uh_sum=0; /* no checksum */
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
				unsigned char proto)
{
	iph->ip_hl = sizeof(struct ip)/4;
	iph->ip_v = 4;
	iph->ip_tos = 0;
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
	iph->ip_sum = ipv4_chksum(sum(iph, sizeof(struct ip)));

	return 0;
}

static inline void mk_ipip_hdr(struct ip &iph, sockaddr_storage *src, sockaddr_storage *dst){
	//build appropriate upper ip header
	iph.ip_hl = sizeof(struct ip)>>2;
	iph.ip_v = IPVERSION;
	iph.ip_tos = IPTOS_ECN_NOT_ECT;
	iph.ip_len = 0; //must be filled each time before send
	iph.ip_id = 0; /* 0 => will be filled automatically by the kernel */
	iph.ip_off = 0; /* frag.: first 3 bits=flags=0, last 13 bits=offset */
	iph.ip_ttl = DEFAULT_IPIP_TTL;//cfg_get(core, core_cfg, udp4_raw_ttl);
	iph.ip_p = IPPROTO_IPIP;
	iph.ip_src = SAv4(src)->sin_addr;
	iph.ip_dst = SAv4(dst)->sin_addr;
	iph.ip_sum = 0; //will be filled by upd_ipip_hdr
}

static inline void upd_ipip_hdr(struct ip &iph, unsigned int len){
	iph.ip_len = RAW_IPHDR_IP_LEN(len);
	iph.ip_sum = ipv4_chksum(sum(&iph, sizeof(struct ip)));
}


void msg_sensor::getInfo(AmArg &ret){
	ret["references"] = (long int)get_ref(this);
}

/*ipip_msg_sensor::ipip_msg_sensor()
{}*/

ipip_msg_sensor::~ipip_msg_sensor()
{
	INFO("destroyed ipip_msg_sensor[%p] raw socket %d",this,s);
	if(s!=-1) close(s);
}

int ipip_msg_sensor::init(const char *src_addr, const char *dst_addr,const char *iface)
{
	//struct ifreq ifr;
	//int ret,raw_input_buf_len = 0;
	//DBG("ipip_msg_sensor::init[%p](%s,%s)",this,src_addr,dst_addr);

	//process parameters
	if(!am_inet_pton(src_addr,&sensor_src_ip)){
		ERROR("invalid src address '%s' for ipip_msg_sensor ",src_addr);
		return 1;
	}
	if(!am_inet_pton(dst_addr,&sensor_dst_ip)){
		ERROR("invalid dst address '%s' for ipip_msg_sensor ",dst_addr);
		return 1;
	}

	mk_ipip_hdr(ipip_hdr,&sensor_src_ip,&sensor_dst_ip);

	//open raw socket
	s = raw_socket(IPPROTO_RAW,NULL,0);
	//s = socket(PF_INET, SOCK_RAW, proto);
	if(s==-1){
		ERROR("can't create raw socket for ipip sensor. errno: %d",errno);
		goto error;
	}

	/*if(iface){
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name,iface,IFNAMSIZ);
		ret = setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(struct ifreq));
		if(ret){
			ERROR("can't bind raw socket to interface %s, errno = %d",iface,errno);
			goto error;
		}
	}*/

	return 0;
error:
	if(s!=-1) close(s);
	return 1;
}

int ipip_msg_sensor::feed(const char* buf, int len,
			 sockaddr_storage* from,
			 sockaddr_storage* to,
			 cstring method, int reply_code)
{
	struct msghdr snd_msg;
	struct iovec iov[2];
	struct ipip_udp_hdr {
		struct ip ipip;
		struct ip ip;
		struct udphdr udp;
	} hdr;
	//unsigned int totlen;
	//int ret;


	/*INFO("ipip_msg_sensor::feed(%p,%d,from,to,method,reply_code)",
		buf,len);*/

	hdr.ipip = ipip_hdr;
	//totlen = len+sizeof(hdr);

	//init msg
	memset(&snd_msg, 0, sizeof(snd_msg));
	snd_msg.msg_name=SAv4(&sensor_dst_ip);
	snd_msg.msg_namelen=SA_len(&sensor_dst_ip);
	snd_msg.msg_iov=&iov[0];
	snd_msg.msg_iovlen=2;
	snd_msg.msg_control=0;
	snd_msg.msg_controllen=0;
	snd_msg.msg_flags=0;

	//hdr
	mk_udp_hdr(&hdr.udp, from, to, (unsigned char*)buf, len, 1);
	mk_ip_hdr(&hdr.ip, &SAv4(from)->sin_addr, &SAv4(to)->sin_addr,
		  len + sizeof(hdr.udp), IPPROTO_UDP);
	upd_ipip_hdr(hdr.ipip,hdr.ip.ip_len + sizeof(struct ip));
	iov[0].iov_base=(char*)&hdr;
	iov[0].iov_len=sizeof(hdr);

	//payload
	iov[1].iov_base=(void*)buf;
	iov[1].iov_len=len;

	/*ret = */sendmsg(s, &snd_msg, 0);
	//DBG("ipip_msg_sensor::feed() sendmsg = %d",ret);
	return 0;
}

void ipip_msg_sensor::getInfo(AmArg &ret){
	char addr[NI_MAXHOST];

	am_inet_ntop(&sensor_src_ip,addr,NI_MAXHOST);
	ret["sensor_src_ip"] = addr;

	am_inet_ntop(&sensor_dst_ip,addr,NI_MAXHOST);
	ret["sensor_dst_ip"] = addr;

	ret["socket"] = s;

	msg_sensor::getInfo(ret);
}

ethernet_msg_sensor::~ethernet_msg_sensor()
{
	INFO("destroyed ethernet_msg_sensor[%p] raw socket %d",this,s);
	if(s!=-1) close(s);
}

int ethernet_msg_sensor::init(const char *ifname, const char *dst_mac)
{
	struct ifreq ifr;
	struct ether_addr eaddr;
	int ret,raw_input_buf_len = 0;

	if(NULL==ifname){
		ERROR("no interface name\n");
		return 1;
	}
	iface_name = ifname;
	if(NULL==dst_mac){
		ERROR("no destination mac address\n");
		return 1;
	}
	sensor_dst_mac = dst_mac;

	DBG("ethernet_msg_sensor::init[%p](%s,%s)\n",this,ifname,dst_mac);

	iface_name = ifname;
	if(iface_name.empty()){
		ERROR("empty interface name\n");
		return 1;
	}
	if(iface_name.size()>sizeof(ifr.ifr_name)){
		ERROR("interface name is too long\n");
		return 1;
	}

	//open raw socket
	s = socket(AF_PACKET, SOCK_RAW, ETH_P_IP);
	if(-1==s){
		ERROR("can't create raw socket for ipip sensor. errno: %d\n",errno);
		goto error;
	}
	ret = setsockopt(s, SOL_SOCKET, SO_RCVBUF, &raw_input_buf_len, sizeof(raw_input_buf_len));
	if(-1==ret){
		WARN("can't set empty receive buffer for raw socket %d with error: %d\n",s,errno);
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name,iface_name.c_str(),iface_name.size());
	ret = ioctl(s, SIOCGIFINDEX, &ifr);
	if(-1==ret){
		ERROR("can't resolve interface name '%s' to index. error: %d\n",
			  iface_name.c_str(),errno);
		goto error;
	}
	iface_index = ifr.ifr_ifindex;
	DBG("index for interface '%s' is %d\n",iface_name.c_str(),iface_index);

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name,iface_name.c_str(),iface_name.size());
	ret = ioctl(s, SIOCGIFHWADDR, &ifr);
	if(-1==ret){
		ERROR("can't get hw address of interface '%s'. error: %d\n",
			  iface_name.c_str(),errno);
		goto error;
	}

	sensor_src_mac = ether_ntoa((struct ether_addr *)ifr.ifr_hwaddr.sa_data);
	DBG("hw address for '%s' is '%s'\n",
		iface_name.c_str(),sensor_src_mac.c_str());

	if(NULL==ether_aton_r(sensor_dst_mac.c_str(),&eaddr)){
		ERROR("invalid sensor destination mac address '%s'\n",sensor_dst_mac.c_str());
		goto error;
	}

	//fill sll address structure
	memset(&addr,0,sizeof(struct sockaddr_ll));
	addr.sll_family=AF_PACKET;
	addr.sll_protocol=htons(ETH_P_IP);
	addr.sll_ifindex = iface_index;
	addr.sll_halen=ETHER_ADDR_LEN;
	memcpy(addr.sll_addr,&eaddr,ETHER_ADDR_LEN);

	//fill ethernet header structure
	memcpy(eth_hdr.ether_dhost,&eaddr,ETHER_ADDR_LEN);
	memcpy(eth_hdr.ether_shost,ifr.ifr_hwaddr.sa_data,ETHER_ADDR_LEN);
	eth_hdr.ether_type = htons(ETH_P_IP);

	return 0;
error:
	if(s!=-1) close(s);
	return 1;
}

int ethernet_msg_sensor::feed(const char* buf, int len,
			 sockaddr_storage* from,
			 sockaddr_storage* to,
			 cstring method, int reply_code)
{
	//int ret;
	struct msghdr snd_msg;
	struct iovec iov[3];
	struct ether_ip_udp_hdr {
		//struct ether_header eth;
		struct ip ip;
		struct udphdr udp;
	} __attribute__ ((__packed__)) hdr;

	/*INFO("ethernet_msg_sensor::feed(%p,%d,from,to,method,reply_code)",
		buf,len);*/

	//memcpy(&hdr.eth,&eth_hdr,sizeof(struct ether_header));

	//init msg
	memset(&snd_msg, 0, sizeof(snd_msg));
	snd_msg.msg_name=&addr;
	snd_msg.msg_namelen=sizeof(struct sockaddr_ll);
	snd_msg.msg_iov=&iov[0];
	snd_msg.msg_iovlen=3;
	snd_msg.msg_control=0;
	snd_msg.msg_controllen=0;
	snd_msg.msg_flags=0;

	//hdr
	mk_udp_hdr(&hdr.udp, from, to, (unsigned char*)buf, len, 1);
	mk_ip_hdr(&hdr.ip, &SAv4(from)->sin_addr, &SAv4(to)->sin_addr,
		  len + sizeof(hdr.udp), IPPROTO_UDP);
	//upd_ipip_hdr(hdr.ipip,hdr.ip.ip_len + sizeof(struct ip));

	//ethernet header
	iov[0].iov_base=(char*)&eth_hdr;
	iov[0].iov_len=sizeof(eth_hdr);

	//ip+udp headers
	iov[1].iov_base=(char*)&hdr;
	iov[1].iov_len=sizeof(hdr);

	//payload
	iov[2].iov_base=(void*)buf;
	iov[2].iov_len=len;

	/*ret = */sendmsg(s, &snd_msg, 0);
	//DBG("ethernet_msg_sensor::feed() sendmsg = %d, error: %d",ret,errno);
	return 0;
}

void ethernet_msg_sensor::getInfo(AmArg &ret){
	ret["interface_name"] = iface_name;
	ret["interface_index"] = iface_index;
	ret["sensor_dst_mac"] = sensor_dst_mac;
	ret["sensor_src_mac"] = sensor_src_mac;
	ret["socket"] = s;

	msg_sensor::getInfo(ret);
}

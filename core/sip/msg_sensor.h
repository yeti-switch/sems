#ifndef _msg_sensor_h_
#define _msg_sensor_h_

#include "atomic_types.h"
#include "AmThread.h"
#include "AmArg.h"
#include "cstring.h"

#include "ip_util.h"

#include "sys/socket.h"
#ifndef __USE_BSD
#define __USE_BSD  /* on linux use bsd version of iphdr (more portable) */
#endif /* __USE_BSD */
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <netinet/ether.h>

#include <set>
#include <string>
using std::set;
using std::string;

struct sockaddr_storage;

class msg_sensor
  : public atomic_ref_cnt
{
public:
  msg_sensor() {}
  virtual ~msg_sensor() {}
  virtual int feed(const char* buf, int len,
		  sockaddr_storage* src_ip,
		  sockaddr_storage* dst_ip,
		  cstring method, int reply_code=0)=0;
  virtual void getInfo(AmArg &ret);
};

class ipip_msg_sensor
  : public msg_sensor
{
	//fields to create upper IPIP header
	sockaddr_storage sensor_src_ip;
	sockaddr_storage sensor_dst_ip;
	struct ip ipip_hdr;

	int s; //raw socket handler

public:
	~ipip_msg_sensor();

	int init(const char *src_addr, const char *dst_addr, const char *iface);
	int feed(const char* buf, int len,
		sockaddr_storage* from,
		sockaddr_storage* to,
		cstring method, int reply_code=0);

	void getInfo(AmArg &ret);
};

class ethernet_msg_sensor
  : public msg_sensor
{
	string iface_name;
	int iface_index;
	string sensor_dst_mac;
	string sensor_src_mac;
	struct sockaddr_ll addr;
	struct ether_header eth_hdr;

	int s; //raw socket handler

public:
	~ethernet_msg_sensor();

	int init(const char *ifname, const char *dst_mac);
	int feed(const char* buf, int len,
		sockaddr_storage* from,
		sockaddr_storage* to,
		cstring method, int reply_code=0);

	void getInfo(AmArg &ret);
};

#endif

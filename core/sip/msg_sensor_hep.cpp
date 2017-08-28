#include "msg_sensor_hep.h"

#include <sys/socket.h>
#include <netdb.h>

#define CHUNK_IP_FAMILY		0x0001
#define CHUNK_IP_PROTO		0x0002
#define CHUNK_SRC_IP		0x0003
#define CHUNK_DST_IP		0x0004
#define CHUNK_SRC_IPv6		0x0005
#define CHUNK_DST_IPv6		0x0006
#define CHUNK_SRC_PORT		0x0007
#define CHUNK_DST_PORT		0x0008
#define CHUNK_TS_SEC		0x0009
#define CHUNK_TS_USEC		0x000a
#define CHUNK_PROTO_TYPE	0x000b
#define CHUNK_CAPTURE_ID	0x000c
#define CHUNK_PAYLOAD		0x000f
#define CHUNK_PAYLOAD_Z		0x0010

#define IP_PROTO_UDP		0x11

#define PROTO_TYPE_SIP		0x01
#define PROTO_TYPE_RTP		0x04

unsigned char hepv3_magic[] = { 0x48, 0x45, 0x50, 0x33 };

hep_msg_sensor::~hep_msg_sensor()
{
	INFO("destroyed hep_msg_sensor[%p] udp socket %d",this,s);
	if(s!=-1) close(s);
}

void hep_msg_sensor::prepare_hep_hdr()
{
	memset(&hep_hdr,0,sizeof(hep_hdr));
	memcpy(hep_hdr.header.id, hepv3_magic, sizeof(hepv3_magic));

	hep_hdr.ip_family(CHUNK_IP_FAMILY,AF_INET);
	hep_hdr.ip_proto(CHUNK_IP_PROTO,IP_PROTO_UDP);

	hep_hdr.src_ip4(CHUNK_SRC_IP);
	hep_hdr.dst_ip4(CHUNK_DST_IP);
	hep_hdr.src_port(CHUNK_SRC_PORT);
	hep_hdr.dst_port(CHUNK_DST_PORT);

	hep_hdr.time_sec(CHUNK_TS_SEC);
	hep_hdr.time_usec(CHUNK_TS_USEC);

    hep_hdr.proto_t(CHUNK_PROTO_TYPE);
    hep_hdr.capt_id(CHUNK_CAPTURE_ID,htonl(capt_id));

    hep_hdr.payload_chunk.vendor_id = htons(0x0000);
    hep_hdr.payload_chunk.type_id   = htons(CHUNK_PAYLOAD);
}

inline void hep_msg_sensor::upd_hep_hdr(
	struct hep_generic &h,
	sockaddr_storage* from,
	sockaddr_storage* to,
	unsigned int len,
	uint8_t proto)
{
	struct timeval now;
	gettimeofday(&now, NULL);

	h.src_ip4.set(SAv4(from)->sin_addr);
	h.src_port.set(SAv4(from)->sin_port);

	h.dst_ip4.set(SAv4(to)->sin_addr);
	h.dst_port.set(SAv4(to)->sin_port);

	h.time_sec.set(htonl(now.tv_sec));
	h.time_usec.set(htonl(now.tv_usec));

	h.proto_t.data = proto;

	h.payload_chunk.length = htons(sizeof(h.payload_chunk) + len);
	h.header.length = htons(sizeof(h) + len);
}

int hep_msg_sensor::init(const char *capture_addr, unsigned short capture_port,
						 int capture_id,
						 const string& capture_password,
						 bool compression_enabled)
{
	if(!am_inet_pton(capture_addr,&capt_addr)){
		ERROR("invalid capture address '%s' for hep_msg_sensor ",
			  capture_addr);
		return 1;
	}
	capt_port = capture_port;
	am_set_port(&capt_addr,capt_port);
	capt_id = capture_id;
	capt_password = capture_password;
	capt_compress = compression_enabled;

	prepare_hep_hdr();

	s = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP);
	if(s==-1){
		ERROR("can't create udp socket for hep sensor. errno: %d",errno);
		goto error;
	}

	/*if(-1==connect(s,(sockaddr *)&capt_addr,sizeof(struct sockaddr_in))) {
		ERROR("can't connect udp socket for hep sensor. errno: %d",errno);
		goto error;
	}*/

	return 0;
error:
	if(s!=-1) close(s);
	return 1;
}

int hep_msg_sensor::feed(const char* buf, int len,
			 sockaddr_storage* from,
			 sockaddr_storage* to,
			 packet_type_t packet_type)
{
	struct msghdr snd_msg;
	struct iovec iov[2];
	struct hep_generic hep;
	uint8_t proto;

	/*DBG("hep_msg_sensor::feed(%p,%d,from,to,method,reply_code)",
		buf,len);*/

	/*if(!method.len && !reply_code) {
		//skip non-SIP packets
		return 0;
	}*/
	switch(packet_type) {
	case PTYPE_SIP:
		proto = PROTO_TYPE_SIP;
		break;
	case PTYPE_RTP:
		proto = PROTO_TYPE_RTP;
		break;
	default:
		return 0;
	}

	hep = hep_hdr;
	upd_hep_hdr(hep,from,to,len, proto);

	memset(&snd_msg, 0, sizeof(snd_msg));
	snd_msg.msg_name=SAv4(&capt_addr);
	snd_msg.msg_namelen=SA_len(&capt_addr);
	snd_msg.msg_iov=iov;
	snd_msg.msg_iovlen=2;
	snd_msg.msg_control=0;
	snd_msg.msg_controllen=0;
	snd_msg.msg_flags=0;

	iov[0].iov_base=(char*)&hep;
	iov[0].iov_len=sizeof(hep);

	iov[1].iov_base=(void*)buf;
	iov[1].iov_len=len;

	/*int ret = */sendmsg(s, &snd_msg, 0);
	//DBG("hep_msg_sensor::feed() sendmsg = %d. errno = %d",ret,errno);
	return 0;
}

void hep_msg_sensor::getInfo(AmArg &ret) {
	ret["capture_address"] = am_inet_ntop(&capt_addr);
	ret["capture_port"] = capt_port;
	ret["capture_password"] = capt_password;
	ret["capture_id"] = capt_id;

	ret["socket"] = s;

	msg_sensor::getInfo(ret);
}


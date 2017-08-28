#pragma once

#include "msg_sensor.h"

/* !TODO:
 * - authentication
 * - compression
 * - own vendor_id
 **/

class hep_msg_sensor
  : public msg_sensor
{
	struct hep_chunk {
		u_int16_t vendor_id;
		u_int16_t type_id;
		u_int16_t length;
	} __attribute__((packed));
	typedef struct hep_chunk hep_chunk_t;

	template <typename Type> struct hep_chunked_data {
		u_int16_t vendor_id;
		u_int16_t type_id;
		u_int16_t length;
		Type data;

		inline void operator() (u_int16_t _type_id)
		{
			vendor_id = htons(0x0000);
			type_id = htons(_type_id);
			length = htons(sizeof(struct hep_chunked_data<Type>));
		}

		inline void operator()(u_int16_t _type_id, Type _data)
		{
			vendor_id = htons(0x0000);
			type_id = htons(_type_id);
			length = htons(sizeof(struct hep_chunked_data<Type>));
			data = _data;
		}

		inline void set(const Type &_data)
		{
			data = _data;
		}
	} __attribute__((packed));

	typedef hep_chunked_data<u_int8_t> hep_chunk_uint8_t;
	typedef hep_chunked_data<u_int16_t> hep_chunk_uint16_t;
	typedef hep_chunked_data<u_int32_t> hep_chunk_uint32_t;
	typedef hep_chunked_data<struct in_addr> hep_chunk_ip4_t;
	//typedef hep_chunked_data<struct in6_addr> hep_chunk_ip6_t;

	struct hep_ctrl {
		char id[4];
		u_int16_t length;
	} __attribute__((packed));
	typedef struct hep_ctrl hep_ctrl_t;

	struct hep_generic {
		hep_ctrl_t         header;
		hep_chunk_uint8_t  ip_family;
		hep_chunk_uint8_t  ip_proto;
		hep_chunk_ip4_t src_ip4;
		hep_chunk_uint16_t src_port;
		hep_chunk_ip4_t dst_ip4;
		hep_chunk_uint16_t dst_port;
		hep_chunk_uint32_t time_sec;
		hep_chunk_uint32_t time_usec;
		hep_chunk_uint8_t  proto_t;
		hep_chunk_uint32_t capt_id;
		hep_chunk_t payload_chunk;
	} __attribute__((packed));

	sockaddr_storage capt_addr;
	unsigned short capt_port;
	int capt_id;

	string capt_password; //TODO
	bool capt_compress; //TODO

	struct hep_generic hep_hdr;

	int s; //udp socket handler

	void prepare_hep_hdr();
	inline void upd_hep_hdr(
		struct hep_generic &h,
		sockaddr_storage* from,
		sockaddr_storage* to,
		unsigned int len,
		uint8_t proto);
public:
	~hep_msg_sensor();

	int init(const char *capture_addr, unsigned short capture_port,
			 int capture_id,
			 const string& capture_password = string(),
			 bool compression_enabled = false);
	int feed(const char* buf, int len,
		sockaddr_storage* from,
		sockaddr_storage* to,
		packet_type_t packet_type);

	void getInfo(AmArg &ret);
};



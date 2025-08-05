/*
 * Copyright (C) 2002-2003 Fhg Fokus
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

#pragma once

#include <string>
#include <map>
#include <vector>
#include <netinet/in.h>
#include "AmPlugIn.h"
#include "AmArg.h"
#include <memory>
#include "AmUtils.h"
#include "sip/types.h"
using std::string;


#define COMFORT_NOISE_PAYLOAD_TYPE 13 // RFC 3389
#define DYNAMIC_PAYLOAD_TYPE_START 96 // range: 96->127, see RFC 1890
/**
 * @file AmSdp.h
 * Definitions for the SDP parser.
 * Refer to the SDP RFC document for any further information.
 */

/** Scratch buffer size. */
#define BUFFER_SIZE 4096

/** \brief c=... line in SDP*/
struct SdpConnection
{
  /** @see NetworkType */
  int network;
  /** @see AddressType */
  AddressType addrType;

  struct sockaddr_in ipv4;
  struct sockaddr_in6 ipv6;
  /** IP address */
  string address;
  int port;

  SdpConnection()
    : network(NT_OTHER), addrType(AT_NONE), port(0)
  {
      bzero(&ipv4, sizeof(struct sockaddr_in));
      bzero(&ipv6, sizeof(struct sockaddr_in6));
  }

  bool operator == (const SdpConnection& other) const;
  /** pretty print */
  string debugPrint() const;
};

/** \brief o=... line in SDP */
struct SdpOrigin
{
  string user;
  uint64_t sessId;
  uint64_t sessV;
  SdpConnection conn;

  SdpOrigin() : user(), conn() {}

  SdpOrigin(const SdpOrigin& other)
    : user(other.user), sessId(other.sessId), sessV(other.sessV),
      conn(other.conn)
  {}

  bool operator == (const SdpOrigin& other) const;
};

/**
 * \brief sdp crypto key info
 *
 * this binds together key, lifetime, mki
 */
struct SdpKeyInfo
{
    string key;
    string lifetime;
    struct {
      uint32_t id;
      uint32_t len;
    } mki;

    SdpKeyInfo() {}

    SdpKeyInfo(const string& key_, string lifetime_ = "")
        : key(key_), lifetime(lifetime_), mki{0, 0} {}

    SdpKeyInfo(const SdpKeyInfo& key)
        : key(key.key), lifetime(key.lifetime)
        , mki(key.mki){}

    string print() const;
};

/**
 * \brief sdp crypto attrribute
 *
 * this binds together tag, crypto suite(profile), keys info(keys), session parameters(sp)
 */
struct SdpCrypto
{
    unsigned int tag;
    CryptoProfile profile;
    bool alt_alias;
    vector<SdpKeyInfo> keys;
    vector<string> sp;

    SdpCrypto() : tag(0), profile(CP_NONE), alt_alias(false) {}

    SdpCrypto(const SdpCrypto& crypto)
      : tag(crypto.tag),
        profile(crypto.profile),
        alt_alias(crypto.alt_alias),
        keys(crypto.keys),
        sp(crypto.sp)
    {}

    string print() const;

    static CryptoProfile str2profile(string str);
    static string profile2str(CryptoProfile profile);
};

struct SdpFingerPrint
{
    string hash;
    string value;

    SdpFingerPrint(){}
    SdpFingerPrint(const SdpFingerPrint& fp) : hash(fp.hash), value(fp.value) {}
};

#ifdef WITH_ZRTP

#define ZRTP_VERSION "1.10"

struct SdpZrtpHash
{
    bool is_use;
    string hash;

    SdpZrtpHash() : is_use(false) {}
    SdpZrtpHash(const SdpZrtpHash& hash) : is_use(hash.is_use), hash(hash.hash){}
};

#endif/*WITH_ZRTP*/

struct SdpIceCandidate
{
    string foundation;
    int  comp_id;
    IceCandidateTransport transport;
    unsigned int priority;
    SdpConnection conn;
    IceCandidateType type;
    SdpConnection rel_conn;
    std::map<string, string> attrs;

    SdpIceCandidate() 
      : foundation(int2str(rand())),
        comp_id(0),
        transport(ICTR_UDP),
        priority((ICT_HOST << 24) | ((rand() & 0xffff) << 8) | (256 - comp_id)), // see rfc5245 4.1.2.1
        type(ICT_HOST)
    {}

    SdpIceCandidate(const SdpIceCandidate& ic)
        : foundation(ic.foundation), comp_id(ic.comp_id)
        , transport(ic.transport), priority(ic.priority)
        , conn(ic.conn), type(ic.type)
        , rel_conn(ic.rel_conn), attrs(ic.attrs){}

    string print() const;
    static IceCandidateType str2type(string str);
};

/** 
 * \brief sdp payload
 *
 * this binds together pt, name, rate and parameters
 */
struct SdpPayload
{
  int    type;   // media type
  int    payload_type; // SDP payload type
  string encoding_name;
  int    clock_rate; // sample rate (Hz)
  string format;
  string sdp_format_parameters;
  int    encoding_param;
  
  SdpPayload() 
    : payload_type(-1), 
      clock_rate(-1), 
      encoding_param(-1) 
  {}

  SdpPayload(int pt) 
    : payload_type(pt), 
      clock_rate(-1), 
      encoding_param(-1) 
  {}

  SdpPayload(int pt, const string& name, int rate, int param) 
    : payload_type(pt), encoding_name(name), 
      clock_rate(rate), encoding_param(param) 
  {}

  SdpPayload(const SdpPayload& other)
    : type(other.type), payload_type(other.payload_type),
      encoding_name(other.encoding_name), clock_rate(other.clock_rate),
      format(other.format), sdp_format_parameters(other.sdp_format_parameters),
      encoding_param(other.encoding_param)
  {}

  bool operator == (int r);

  bool operator == (const SdpPayload& other) const;
};

/** \brief a=... line in SDP */
struct SdpAttribute
{
  string attribute;
  string value;

  // property attribute
  SdpAttribute(const string& attribute,
	       const string& value)
    : attribute(attribute), value(value) { }

  // value attribute
  SdpAttribute(const string& attribute)
    : attribute(attribute) { }

  SdpAttribute(const SdpAttribute& other)
    : attribute(other.attribute), value(other.value) {}

  string print() const;

  bool operator == (const SdpAttribute& other) const;
  bool operator < (const SdpAttribute& other) const;
};

/** \brief m=... line in SDP */
struct SdpMedia
{
  enum Direction {
    DirBoth=0,
    DirActive=1,
    DirPassive=2,
    DirUndefined=3
  };

  int           type;
  unsigned int  port;
  unsigned int  rtcp_port; // a=rtcp:
  unsigned int  nports;
  TransProt     transport;
  int           frame_size;
  SdpConnection conn; // c=
  SdpConnection rtcp_conn; // a=rtcp:
  Direction     dir;  // a=direction
  Setup         setup;
  string        fmt;  // format in case proto != RTP/AVP or RTP/SAVP
  unsigned int  ssrc;
  string        cname;

  // sendrecv|sendonly|recvonly|inactive
  bool          send;
  bool          recv;
  bool          has_mode_attribute;

  bool          is_multiplex; // a=rtcp-mux

  std::vector<SdpPayload> payloads;
  /* rtp/savr transport attribute*/
  std::vector<SdpCrypto> crypto;
  /* udp/tls/rtp/savr  transport attribute*/
  SdpFingerPrint fingerprint;
#ifdef WITH_ZRTP
  SdpZrtpHash zrtp_hash;
#endif/*WITH_ZRTP*/
  // ice attribute
  bool is_ice;
  string ice_pwd;
  string ice_ufrag;
  std::vector<SdpIceCandidate> ice_candidate;

  std::vector<SdpAttribute> attributes; // unknown attributes

  bool operator == (const SdpMedia& other) const;

  SdpMedia()
    : type(MT_NONE),
      port(0),
      rtcp_port(0),
      nports(0),
      transport(TP_NONE),
      frame_size(20),
      dir(DirUndefined),
      setup(S_UNDEFINED),
      ssrc(0),
      send(true),
      recv(true),
      has_mode_attribute(false),
      is_multiplex(false),
      is_ice(false)
  {}

  /** pretty print */
  string debugPrint() const;

  static string type2str(int type);
  static TransProt str2transport(string type);
  /**
   * Checks which payloads are compatible with the payload provider,
   * inserts them into the answer, compute send/recv attributes
   * and direction according to the offer.
   */
  void calcAnswer(const AmPayloadProvider* payload_prov, 
		  SdpMedia& answer) const;

  void set_mode_if_missed(bool _send, bool _recv);
  
  bool is_dtls_udptl() const {
       return transport == TP_UDPTLSUDPTL;
  }

  bool is_udptl() const {
       return transport == TP_UDPTL;
  }

  bool is_dtls_srtp() const {
      return transport == TP_UDPTLSRTPSAVP ||
             transport == TP_UDPTLSRTPSAVPF;
  }

  bool is_simple_srtp() const {
      return transport == TP_RTPSAVP ||
             transport == TP_RTPSAVPF;
  }

  bool is_simple_rtp() const {
      return transport == TP_RTPAVP ||
             transport == TP_RTPAVPF;
  }

  bool is_use_ice() const {
      return is_ice;
  }
};

/**
 * \brief handling SDP attribute "rtcp"
 */
class RtcpAddress
{
  private:
    string nettype, addrtype, address;
    bool parse(const string &src);
    int port;

  public:
    RtcpAddress(const string &attr_value);
    bool hasAddress() { return !address.empty(); }
    void setAddress(const string &addr) { address = addr; }
    const string& getAddress() { return address; }
    void setPort(int _port) { port = _port; }
    int getPort() { return port; }
    string print();
};

/**
 * \brief The SDP parser class.
 */
class AmSdp
{

  /**
   * Find payload by name, return cloned object
   */
  vector<const SdpPayload*> findPayload(const string& name) const;

public:
  // parsed SDP definition
  unsigned int     version;     // v=
  SdpOrigin        origin;      // o=
  string           sessionName; // s= 
  string           uri;         // u=
  SdpConnection    conn;        // c=
  bool use_ice;
  string ice_pwd;
  string ice_ufrag;
  Setup setup;
  std::vector<SdpAttribute> attributes; // unknown session level attributes

  bool send;
  bool recv;

  std::vector<SdpMedia> media;  // m= ... [a=rtpmap:...]+
  //TODO: t= lines

  SdpOrigin        l_origin;      // local origin (o= )
    
  AmSdp();
  AmSdp(const AmSdp& p_sdp_msg);

  /** 
   * Parse the SDP message passed as an argument.
   * @return !=0 if error encountered.
   */
  int parse(const char* _sdp_msg);

  /**
   * Prints the current SDP structure
   * into a proper SDP message.
   */
  void print(string& body) const;

  /** get telephone event payload */
  vector<const SdpPayload*> telephoneEventPayload() const;

  /**
   * Test if remote UA supports 'telefone_event'.
   */
  //bool hasTelephoneEvent();

  bool operator == (const AmSdp& other) const;

  /**
   * Clear all parsed values.
   */
  void clear();

  void getInfo(AmArg &ret);
};

// Local Variables:
// mode:C++
// End:

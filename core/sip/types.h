#pragma once

#include <string>
using std::string;

/** network type */
enum NetworkType { NT_OTHER=0, NT_IN };
/** address type */
enum AddressType { AT_NONE=0, AT_V4, AT_V6 };
/** media type */
enum MediaType { MT_NONE=0, MT_AUDIO, MT_VIDEO, MT_APPLICATION, MT_TEXT, MT_MESSAGE, MT_IMAGE };
/** transport protocol */
enum TransProt { TP_NONE=0, TP_RTPAVP, TP_RTPAVPF, TP_UDP, TP_RTPSAVP, TP_UDPTL, TP_RTPSAVPF, TP_UDPTLSRTPSAVP, TP_UDPTLSRTPSAVPF };
/** srtp profile */
enum CryptoProfile { CP_NONE=0, CP_AES128_CM_SHA1_80 = 1, CP_AES128_CM_SHA1_32 = 2, CP_F8128_HMAC_SHA1_80 = 4, CP_NULL_SHA1_80 = 5, CP_NULL_SHA1_32 = 6 };

enum IceCandidateType { ICT_NONE = 0, ICT_HOST = 0x7E, ICT_SRFLX = 0x64, ICT_PRFLX = 0x5A, ICT_RELAY = 0x40 }; // see rfc5245 4.1.2.1

enum IceCandidateTransport{ ICTR_UDP = 0, ICTR_TCP };

string transport_p_2_str(int tp);

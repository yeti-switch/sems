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
enum TransProt { TP_NONE=0, TP_RTPAVP, TP_RTPAVPF, TP_UDP, TP_RTPSAVP, TP_UDPTL, TP_RTPSAVPF, TP_UDPTLSRTPSAVP, TP_UDPTLSRTPSAVPF, TP_UDPTLSUDPTL};
/** srtp profile */
enum CryptoProfile {
    CP_NONE=0, CP_AES128_CM_SHA1_80 = 1, CP_AES128_CM_SHA1_32 = 2, CP_NULL_SHA1_80 = 5, CP_NULL_SHA1_32 = 6, // see rfc5764 4.1.2
    CP_AES256_CM_SHA1_80 = 3, CP_AES256_CM_SHA1_32 = 4,                                                      // see https://tools.ietf.org/id/draft-lennox-avtcore-dtls-srtp-bigaes-01.html
//    CP_AEAD_AES_128_GCM = 7, CP_AEAD_AES_256_GCM = 8,                                                        // see rfc7714 14.2
//    CP_AES192_CM_SHA1_80 = 17, CP_AES192_CM_SHA1_32 = 18                                                     // unused numbers
                                                                                                             // see https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml
};

enum IceCandidateType { ICT_NONE = 0, ICT_HOST = 0x7E, ICT_SRFLX = 0x64, ICT_PRFLX = 0x5A, ICT_RELAY = 0x40 }; // see rfc5245 4.1.2.1

enum IceCandidateTransport{ ICTR_UDP = 0, ICTR_TCP };

enum Setup { S_HOLD=0, S_ACTIVE=1, S_PASSIVE=2, S_ACTPASS=3, S_UNDEFINED=4 }; //see rfc4145 4.

string transport_p_2_str(int tp);

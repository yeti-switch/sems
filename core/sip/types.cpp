#include "types.h"

#include <sstream>

string transport_p_2_str(int tp)
{
    switch (tp) {
    case TP_RTPAVP:         return "RTP/AVP";
    case TP_RTPAVPF:        return "RTP/AVPF";
    case TP_UDP:            return "UDP";
    case TP_RTPSAVP:        return "RTP/SAVP";
    case TP_RTPSAVPF:       return "RTP/SAVPF";
    case TP_UDPTLSRTPSAVP:  return "UDP/TLS/RTP/SAVP";
    case TP_UDPTLSRTPSAVPF: return "UDP/TLS/RTP/SAVPF";
    case TP_UDPTLSUDPTL:    return "UDP/TLS/UDPTL";
    case TP_UDPTL:          return "udptl";
    default:                return "<unknown_media_type>";
    }
}

string addr_t_2_str(int at)
{
    switch (at) {
    case AT_V4: return "IP4";
    case AT_V6: return "IP6";
    default:    return "<unknown address type>";
    }
}

string net_t_2_str(int nt)
{
    switch (nt) {
    case NT_IN: return "IN";
    default:    return "<unknown network type>";
    }
}

string media_t_2_str(int mt)
{
    switch (mt) {
    case MT_AUDIO:       return "audio";
    case MT_VIDEO:       return "video";
    case MT_APPLICATION: return "application";
    case MT_TEXT:        return "text";
    case MT_MESSAGE:     return "message";
    case MT_IMAGE:       return "image";
    default:             return "<unknown media type>";
    }
}

string profile_t_2_str(int pt, bool alternative)
{
    switch (pt) {
    case CP_AES128_CM_SHA1_80: return "AES_CM_128_HMAC_SHA1_80";
    case CP_AES128_CM_SHA1_32: return "AES_CM_128_HMAC_SHA1_32";
    case CP_AES256_CM_SHA1_80: return alternative ? "AES_CM_256_HMAC_SHA1_80" : "AES_256_CM_HMAC_SHA1_80";
    case CP_AES256_CM_SHA1_32: return alternative ? "AES_CM_256_HMAC_SHA1_32" : "AES_256_CM_HMAC_SHA1_32";
    case CP_NULL_SHA1_80:      return "NULL_HMAC_SHA1_80";
    case CP_NULL_SHA1_32:
        return "NULL_HMAC_SHA1_32";
        //         case CP_AEAD_AES_128_GCM: return "AEAD_AES_256_GCM";
        //         case CP_AEAD_AES_256_GCM: return "AEAD_AES_256_GCM";
        //         case CP_AES192_CM_SHA1_80: return "AES_CM_192_HMAC_SHA1_80";
        //         case CP_AES192_CM_SHA1_32: return "AES_CM_192_HMAC_SHA1_32";
    default:
    {
        std::ostringstream stringStream;
        stringStream << "<unknown_profile_type " << pt << ">";
        return stringStream.str();
    }
    }
}

string transport_ice_2_str(int tp)
{
    switch (tp) {
    case ICTR_UDP:     return "UDP";
    case ICTR_TCP:     return "TCP";
    case ICTR_TCP_ACT: return "TCP-ACT";
    default:           return "<unknown transport type>";
    }
}

string ice_candidate_2_str(int ic)
{
    switch (ic) {
    case ICT_HOST:  return "host";
    case ICT_PRFLX: return "prflx";
    case ICT_SRFLX: return "srflx";
    case ICT_RELAY: return "relay";
    default:        return "<unknown candidate type>";
    }
}

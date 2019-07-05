#include "types.h"

string transport_p_2_str(int tp)
{
    switch(tp) {
        case TP_RTPAVP: return "RTP/AVP";
        case TP_RTPAVPF: return "RTP/AVPF";
        case TP_UDP: return "UDP";
        case TP_RTPSAVP: return "RTP/SAVP";
        case TP_RTPSAVPF: return "RTP/SAVPF";
        case TP_UDPTLSRTPSAVP: return "UDP/TLS/RTP/SAVP";
        case TP_UDPTLSRTPSAVPF: return "UDP/TLS/RTP/SAVPF";
        case TP_UDPTL: return "UDPTL";
        default: return "<unknown_media_type>";
    }
}

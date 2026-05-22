#include "AmComfortNoiseSender.h"
#include "AmRtpStream.h"
#include "rtp/comfort_noise.h"

AmComfortNoiseSender::AmComfortNoiseSender()
    : enabled(false)
    , level(0)
    , interval_ts(0)
    , last_ts(0)
    , last_ts_set(false)
{
}

void AmComfortNoiseSender::enable(unsigned int _level, unsigned int _interval_ts)
{
    level       = _level & 0x7f;
    interval_ts = _interval_ts;
    last_ts_set = false;
    enabled     = true;
}

void AmComfortNoiseSender::disable()
{
    enabled = false;
}

bool AmComfortNoiseSender::send(unsigned int ts, int remote_pt, AmRtpStream *stream)
{
    if (!enabled || remote_pt < 0)
        return false;

    if (last_ts_set && interval_ts && (ts - last_ts) < interval_ts)
        return false;

    cn_payload_t cn;
    cn.r     = 0;
    cn.level = level;
    stream->compile_and_send(remote_pt, false, ts, reinterpret_cast<unsigned char *>(&cn), sizeof(cn_payload_t));

    last_ts     = ts;
    last_ts_set = true;
    return true;
}

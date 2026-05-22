#pragma once

class AmRtpStream;

// Comfort Noise (RFC 3389) sender, driven externally (e.g. from put_on_idle).
class AmComfortNoiseSender {
    bool         enabled;
    unsigned int level;
    unsigned int interval_ts;
    unsigned int last_ts;
    bool         last_ts_set;

  public:
    AmComfortNoiseSender();

    void enable(unsigned int level, unsigned int interval_ts);
    void disable();
    bool isEnabled() const { return enabled; }

    bool send(unsigned int ts, int remote_pt, AmRtpStream *stream);
};

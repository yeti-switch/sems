#pragma once

#include "AmEvent.h"

#include <string>

/** \brief event fired on RTP timeout */
class AmRtpTimeoutEvent : public AmEvent {
  public:
    AmRtpTimeoutEvent()
        : AmEvent(0)
    {
    }
    ~AmRtpTimeoutEvent() {}
};

/** \brief event fired on RTP sending error */
class AmRtpSendingErrorEvent : public AmEvent {
  public:
    AmRtpSendingErrorEvent()
        : AmEvent(0)
    {
    }
    ~AmRtpSendingErrorEvent() {}
};

/** \brief event fired when ICE connectivity check fails to nominate a pair */
class AmIceConnectivityFailedEvent : public AmEvent {
  public:
    AmIceConnectivityFailedEvent()
        : AmEvent(0)
    {
    }
    ~AmIceConnectivityFailedEvent() {}
};

/**
 * \brief event fired once per media session when the media path becomes usable:
 *  - plain RTP/SRTP/UDPTL: current connection picked on the transport;
 *  - DTLS+RTP / DTLS+UDPTL / ZRTP: after SRTP keys are negotiated;
 *  - ICE RTP/SRTP/UDPTL: after a candidate pair is nominated;
 *  - ICE DTLS/ZRTP variants: after SRTP keys are negotiated.
 * Re-armed on ICE restart. setup_time_ms — duration from RTP stream
 * construction (or last ICE-restart re-arm) to event fire, in milliseconds.
 */
class MediaEstablishedEvent : public AmEvent {
  public:
    unsigned long setup_time_ms;

    explicit MediaEstablishedEvent(unsigned long setup_ms)
        : AmEvent(0)
        , setup_time_ms(setup_ms)
    {
    }
    ~MediaEstablishedEvent() {}
};

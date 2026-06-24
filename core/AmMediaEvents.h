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
 * Re-armed on ICE restart.
 */
class MediaEstablishedEvent : public AmEvent {
  public:
    MediaEstablishedEvent()
        : AmEvent(0)
    {
    }
    ~MediaEstablishedEvent() {}
};

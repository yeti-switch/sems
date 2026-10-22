#pragma once

#include "AmEvent.h"

#include <string>
#include <vector>

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
 * \brief event fired when ICE concludes for a media endpoint: every component has a selected pair
 * (RFC 5245 8.1.2). Fired again if the selection changes (re-nomination, ICE restart).
 * default_pair_changed: selected pairs differ from the default destinations (m=/c=/a=rtcp) of the last
 * offer/answer, the controlling agent has to send an updated offer (RFC 5245 9.1.2.2).
 */
class AmIceCompletedEvent : public AmEvent {
  public:
    std::vector<int> media_indexes;
    bool             controlling;
    bool             default_pair_changed;

    AmIceCompletedEvent(std::vector<int> indexes, bool controlling, bool default_pair_changed)
        : AmEvent(0)
        , media_indexes(std::move(indexes))
        , controlling(controlling)
        , default_pair_changed(default_pair_changed)
    {
    }
    ~AmIceCompletedEvent() {}
};

/**
 * \brief event fired once per media endpoint when the transport path becomes usable:
 *  - plain RTP/SRTP/UDPTL: current connection picked on the transport;
 *  - DTLS+RTP / DTLS+UDPTL / ZRTP: after SRTP keys are negotiated;
 *  - ICE RTP/SRTP/UDPTL: after a candidate pair is nominated;
 *  - ICE DTLS/ZRTP variants: after SRTP keys are negotiated.
 * Re-armed on ICE restart.
 */
class MediaEstablishedEvent : public AmEvent {
  public:
    unsigned long    setup_time_ms;
    std::vector<int> media_indexes;

    MediaEstablishedEvent(unsigned long setup_ms, std::vector<int> indexes)
        : AmEvent(0)
        , setup_time_ms(setup_ms)
        , media_indexes(std::move(indexes))
    {
    }
    ~MediaEstablishedEvent() {}
};

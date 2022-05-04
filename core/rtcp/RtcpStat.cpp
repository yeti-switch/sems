#include "RtcpStat.h"
#include "AmRtpStream.h"

#include <memory>

#include <strings.h>

#define RTP_SEQ_MOD (1<<16)

RtcpUnidirectionalStat::RtcpUnidirectionalStat()
{ 
    bzero(this,sizeof(RtcpUnidirectionalStat));
}

RtcpBidirectionalStat::RtcpBidirectionalStat()
  : current_rx(nullptr),
    rtcp_rr_sent(0), rtcp_rr_recv(0),
    rtcp_sr_sent(0), rtcp_sr_recv(0),
    max_seq(0),
    cycles(0),
    received(0),
    received_prior(0),
    expected_prior(0),
    transit(0),
    total_lost(0),
    fraction_lost(0),
    sr_lsr(0)
{
    timerclear(&rx_recv_time);
    timerclear(&start);
}

void RtcpBidirectionalStat::init_seq(uint32_t ssrc, uint16_t seq)
{
    probation = MIN_SEQUENTIAL;
    base_seq = seq;
    max_seq = seq;
    bad_seq = RTP_SEQ_MOD - 1;
    cycles = 0;
    total_lost = 0;
    fraction_lost = 0;
    received = 0;
    received_prior = 0;
    expected_prior = 0;
    transit = 0;
    if(rx.size() < MAX_RX_STATS || rx.find(ssrc) != rx.end()) {
        current_rx = &rx[ssrc];
        current_rx->rtcp_jitter = 0;
    } else {
        current_rx = 0;
    }
}

int RtcpBidirectionalStat::update_seq(uint32_t ssrc, uint16_t seq)
{
    uint16_t udelta = seq - max_seq;

    /* Source is not valid until MIN_SEQUENTIAL packets with
     * sequential sequence numbers have been received. */
    if(probation) {
        //packet is in sequence
        if (seq == max_seq + 1) {
            probation--;
            max_seq = seq;
            if (probation == 0) {
                init_seq(ssrc, seq);
                received++;
                return 1;
            }
        } else {
            probation = MIN_SEQUENTIAL - 1;
            max_seq = seq;
        }
        return 0;
    } else if (udelta < MAX_DROPOUT) {
        //in order, with permissible gap
        if (seq < max_seq) {
            //Sequence number wrapped - count another 64K cycle.
            cycles += RTP_SEQ_MOD;
        }
        max_seq = seq;
    } else if (udelta <= RTP_SEQ_MOD - MAX_MISORDER) {
        //the sequence number made a very large jump
        if (seq == bad_seq) {
            /* Two sequential packets -- assume that the other side
            * restarted without telling us so just re-sync
            * (i.e., pretend this was the first packet). */
            init_seq(ssrc, seq);
        } else {
            bad_seq = (seq + 1) & (RTP_SEQ_MOD-1);
            return 0;
        }
    } else {
        //duplicate or reordered packet
        //!TODO: update Recv stream statistics
        return 1;
    }

    received++;
    return 1;
}

void RtcpBidirectionalStat::update_lost()
{
    /*DBG("update_lost: cycles: %d, max_seq: %d, received: %d, base_seq: %d, expected_prior: %d, received_prior: %d",
        cycles, max_seq, received, base_seq, expected_prior, received_prior);*/

    if(!max_seq) return;

    uint32_t extended_max = cycles + max_seq;
    uint32_t expected =  extended_max - base_seq + 1;

    total_lost = expected - received;

    uint32_t expected_interval = expected - expected_prior;
    expected_prior = expected;

    uint32_t received_interval = received - received_prior;
    received_prior = received;

    uint32_t lost_interval = expected_interval - received_interval;
    if (expected_interval == 0 || lost_interval <= 0) {
        fraction_lost = 0;
    } else {
        fraction_lost = (lost_interval << 8) / expected_interval;
    }
    //current_rx->loss_period.update((uint32_t)fraction_lost);
}

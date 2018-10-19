#include "RtcpStat.h"

#include <cmath>
#include <memory>

#include <strings.h>

#define RTP_SEQ_MOD (1<<16)

MathStat::MathStat()
/*  : n(0),
    max(0),
    min(0),
    last(0),
    mean(0),
    variance_multiplied_by_n(0)*/
{
    bzero(this,sizeof(MathStat));
}

void MathStat::update(int v)
{
    float diff;

    last = v;

    if(n++) {
        if(min > v) min = v;
        if(max < v) max = v;
    } else {
        min = max = v;
    }

    diff = v-mean;
    mean += diff/n;

    variance_multiplied_by_n += diff*mean;
}

long double MathStat::variance() const
{
    if(n==0) return 0;
    return variance_multiplied_by_n/n;
}

long double MathStat::sd() const
{
    if(n==0) return 0;
    return std::sqrt(variance_multiplied_by_n/n);
}

RtcpBidirectionalStat::RtcpBidirectionalStat()
  : sr_lsr(0)
{
    timerclear(&rx_recv_time);
}

void RtcpBidirectionalStat::init_seq(uint16_t seq)
{
    base_seq = seq;
    max_seq = seq;
    bad_seq = RTP_SEQ_MOD - 1;
    cycles = 0;
    received = 0;
    received_prior = 0;
    expected_prior = 0;
}

int RtcpBidirectionalStat::update_seq(uint16_t seq)
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
                init_seq(seq);
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
            init_seq(seq);
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
    //rx.loss_period.update(fraction_lost);
}

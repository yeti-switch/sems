#pragma once

#include "AmThread.h"

#include <time.h>
#include <stdint.h>

#include <unordered_map>
#include <cmath>

const int MAX_DROPOUT = 3000;
const int MAX_MISORDER = 100;
const int MIN_SEQUENTIAL = 2;

template <typename T = int>
struct MathStat
{
    int n;                                /* number of samples    */
    T max;                                /* maximum value        */
    T min;                                /* minimum value        */
    T last;                               /* last value           */
    float mean;                           /* mean                 */
    double variance_multiplied_by_n;      /* variance * n         */

    MathStat()
      /*: n(0),
        max(0),
        min(0),
        mean(0),
        variance_multiplied_by_n(0)*/
    {
        bzero(this,sizeof(MathStat<T>));
    }

    inline void update(T v) {
        float diff;

        last = v;

        if(n++) {
            if(min > v) min = v;
            if(max < v) max = v;
        } else {
            min = v;
            max = v;
        }

        diff = v-mean;
        mean += diff/n;

        variance_multiplied_by_n += diff*(v-mean);
    }

    inline long double sd() const //standard deviation
    {
        if(n==0) return 0;
        return std::sqrt(variance_multiplied_by_n/n);
    }
};

struct RtcpUnidirectionalStat
{
    timeval     update;        /**< Time of last update.                   */
    unsigned    update_cnt;	   /**< Number of updates (to calculate avg)   */
    uint32_t    pkt;           /**< Total number of packets                */
    uint32_t    bytes;         /**< Total number of payload/bytes          */
    unsigned    discard;       /**< Total number of discarded packets.     */
    unsigned    loss;          /**< Total number of packets lost           */
    unsigned    reorder;       /**< Total number of out of order packets   */
    unsigned    dup;           /**< Total number of duplicates packets     */

    MathStat<>  loss_period;   /**< Loss period statistics (in usec)       */

    struct {
        unsigned    burst:1;   /**< Burst/sequential packet lost detected  */
        unsigned    random:1;  /**< Random packet lost detected.           */
    } loss_type;               /**< Types of loss detected.                */

    int         rtcp_jitter;   /** scaled RTCP jitter                      */
};

struct RtcpBidirectionalStat
  : public AmMutex
{
    using RxStatMap = std::unordered_map<unsigned int, RtcpUnidirectionalStat>;

    timeval    start;             /**< Time when session was created       */

    RtcpUnidirectionalStat    tx; /**< Send stream statistics.             */
    //RxStatMap    rx;              /**< Recv streams statistics.            */
    RtcpUnidirectionalStat    rx; /**< Recv stream statistics.             */

    uint32_t    rtp_tx_last_ts;   /**< Last TX RTP timestamp.              */
    uint16_t    rtp_tx_last_seq;  /**< Last TX RTP sequence.               */

    // https://tools.ietf.org/html/rfc3550

    uint16_t max_seq;        /* highest seq. number seen */
    uint32_t cycles;         /* shifted count of seq. number cycles */
    uint32_t base_seq;       /* base seq number */
    uint32_t bad_seq;        /* last 'bad' seq number + 1 */
    uint32_t probation;      /* sequ. packets till source is valid */
    uint32_t received;       /* packets received */
    uint32_t expected_prior; /* packet expected at last interval */
    uint32_t received_prior; /* packet received at last interval */
    uint32_t transit;        /* relative trans time for prev pkt */

    timeval  rx_recv_time;

    uint32_t total_lost;
    uint8_t  fraction_lost;

    uint32_t sr_lsr;         /* last SR timestamp from sender report */
    timeval  sr_recv_time;

    MathStat<uint32_t>       rtt;          /**< Round trip delay statistic(in usec) */
    MathStat<long>           rx_delta;     /**< rx delta statistic(in usec)  */
    MathStat<double>         jitter;       /** rx jitter statistic(in usec) */
    MathStat<uint32_t>       rtcp_jitter;         /** rx jitter statistic(in usec) */
    MathStat<uint32_t>       rtcp_remote_jitter;  /** rx jitter from remote reports statistic(in usec) */

    void init_seq(uint16_t seq);
    int update_seq(uint16_t seq);
    void update_lost();

    RtcpBidirectionalStat();
};


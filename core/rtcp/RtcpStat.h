#pragma once

#include "AmThread.h"

#include <time.h>
#include <stdint.h>

#include <unordered_map>

const int MAX_DROPOUT = 3000;
const int MAX_MISORDER = 100;
const int MIN_SEQUENTIAL = 2;

struct MathStat
{
    int n;                              /* number of samples    */
    int max;                            /* maximum value        */
    int min;                            /* minimum value        */
    int last;                           /* last value           */
    float mean;                         /* mean                 */
    double variance_multiplied_by_n;    /* variance * n         */

    MathStat();
    void update(int val);

    long double variance() const;
    long double sd() const;         //standard deviation
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

    MathStat    loss_period;   /**< Loss period statistics (in usec)       */

    struct {
        unsigned    burst:1;   /**< Burst/sequential packet lost detected  */
        unsigned    random:1;  /**< Random packet lost detected.           */
    } loss_type;               /**< Types of loss detected.                */

    MathStat    jitter;        /**< Jitter statistics (in usec)            */
};

struct RtcpBidirectionalStat
  : public AmMutex
{
    using RxStatMap = std::unordered_map<unsigned int, RtcpUnidirectionalStat>;

    timeval    start;             /**< Time when session was created       */

    RtcpUnidirectionalStat    tx; /**< Send stream statistics.             */
    //RxStatMap    rx;              /**< Recv streams statistics.            */
    RtcpUnidirectionalStat    rx; /**< Recv stream statistics.             */
    MathStat     rtt;             /**< Round trip delay statistic(in usec) */

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

    //uint32_t jitter;         /* estimated jitter */
    timeval  rx_recv_time;

    uint32_t total_lost;
    uint8_t  fraction_lost;

    uint32_t sr_lsr;         /* last SR timestamp from sender report */
    timeval  sr_recv_time;

    void init_seq(uint16_t seq);
    int update_seq(uint16_t seq);
    void update_lost();

    RtcpBidirectionalStat();
};


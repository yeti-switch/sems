#pragma once

#include <time.h>
#include <stdint.h>

#include <unordered_map>

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

    long double sd() const;
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
{
    using RxStatMap = std::unordered_map<unsigned int, RtcpUnidirectionalStat>;

    timeval    start;             /**< Time when session was created       */

    RtcpUnidirectionalStat    tx; /**< Send stream statistics.             */
    //RxStatMap    rx;              /**< Recv streams statistics.            */
    RtcpUnidirectionalStat    rx; /**< Recv stream statistics.             */
    MathStat     rtt;             /**< Round trip delay statistic(in usec) */

    uint32_t    rtp_tx_last_ts;   /**< Last TX RTP timestamp.              */
    uint16_t    rtp_tx_last_seq;  /**< Last TX RTP sequence.               */
};


#pragma once

#include <vector>
#include <sys/socket.h>

#include "atomic_types.h"
#include "bitops.h"
#include "ampi/MixerAPI.h"

using std::vector;


#define _hot __attribute__((optimize("-O3")))

#define UDP_MESSAGE_MAX 65508

// 20*rate/1000 = frames
// 1MB ~500 каналов по 44100
#define TX_RING_MMAP_ORDER 20
#define TX_RING_MMAP_SIZE  (1<<TX_RING_MMAP_ORDER)
#define TX_RING_MMAP_MASK  (TX_RING_MMAP_SIZE-1)
// 8192
#define TX_RING_RX_ORDER   13
#define TX_RING_RX_SIZE    (1<<TX_RING_RX_ORDER)
#define TX_RING_RX_MASK    (TX_RING_RX_SIZE-1)

// 2MB
#define RX_RING_MMAP_ORDER 21
#define RX_RING_MMAP_SIZE  (1<<RX_RING_MMAP_ORDER)
#define RX_RING_MMAP_MASK  (RX_RING_MMAP_SIZE-1)

// 8192
#define RX_RING_RX_ORDER   13
#define RX_RING_RX_SIZE    (1<<RX_RING_RX_ORDER)
#define RX_RING_RX_MASK    (RX_RING_RX_SIZE-1)



class TxRing {
    const vector<sockaddr_storage>& neighbor_saddr;
    int                             sockfd,
                                    offset;

    unsigned int                    last_tx,
                                    pending;

    unsigned char                   *buffer;
    MixerFrame                       tx[TX_RING_RX_SIZE];

    void    send(struct iovec *iov, int iov_len);
    void    done();
public:
    TxRing(int sd, const vector<sockaddr_storage>& neighbor_saddr);
    ~TxRing();

    void    put(unsigned long long ts,
                uint64_t id,
                unsigned output_sample_rate,
                unsigned char *data,
                unsigned size);
};


class RxRing {
    unsigned char       *buffer;
    int                 offset,
                        last_rx;

    RxFrame             *next_rx_frame;
    void                prepare_next_frame(ssize_t length);

public:
    static RxFrame     rx[RX_RING_RX_SIZE];

    RxRing();
    ~RxRing();

    void  handler(uint32_t ev, int fd) _hot;
};

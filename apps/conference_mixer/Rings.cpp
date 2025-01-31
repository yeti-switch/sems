#include <string>
#include <utility>

#include <sys/epoll.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <linux/types.h>
#include <sip/ip_util.h>

#include "Rings.h"
#include "Mixer.h"

// __asm__ __volatile__("nop");


RxFrame     RxRing::rx[RX_RING_RX_SIZE];

TxRing::TxRing(int sd, const vector<sockaddr_storage> &neighbor_saddr)
  : neighbor_saddr(neighbor_saddr),
    sockfd(sd),
    offset(0),
    last_tx(0),
    pending(0)
{
    buffer = (unsigned char *)mmap(NULL, TX_RING_MMAP_SIZE, PROT_READ | PROT_WRITE,
                                         MAP_ANONYMOUS | MAP_PRIVATE , -1, 0);
    if (buffer == MAP_FAILED)
        throw string("RxRing: mmap() call failed"); // throw std::bad_alloc();
}


TxRing::~TxRing()
{
    munmap(buffer, TX_RING_MMAP_SIZE);
}


/** Transmit prepared ring to all neighbors */
void TxRing::send(struct iovec *iov, int iov_len)
{
    struct msghdr mh = {};

    mh.msg_iov = iov;
    mh.msg_iovlen = iov_len;

    for (const auto&  saddr: neighbor_saddr) {
        mh.msg_name = (caddr_t) &saddr;
        mh.msg_namelen = SA_len(&saddr);

        if (!am_get_port(&saddr))
            continue;

        //fprintf(stderr, "#SEND to %s:%d\n",  am_inet_ntop(&saddr).c_str(), am_get_port(&saddr));

        ssize_t ret = ::sendmsg(sockfd, &mh, MSG_NOSIGNAL);

        if (ret < 0)
            ERROR("sendmsg(): %m");
    }
}


// TODO: multiframe support must be added
void TxRing::done()
{
    if (last_tx == pending)
        return;

    //int iov_len = 1; // delta last_tx - last_ring_tx

    struct iovec iov[1] = {};

    for ( ; last_tx != pending; ++last_tx) {
        MixerFrame *frame = &tx[last_tx & TX_RING_RX_MASK];

        MixerFrameHdr *hdr = (MixerFrameHdr *)frame->data;

        iov[0].iov_base = (caddr_t)hdr;
        iov[0].iov_len  = hdr->length + sizeof(MixerFrameHdr);
    }

    send((struct iovec*)&iov, 1);
}


/** Every ConferenceMedia() has its own TxRing object, no race here */
void TxRing::put(unsigned long long ts, uint64_t id, unsigned output_sample_rate,
                 unsigned char *data, unsigned size)
{
    //fprintf(stderr, "#EXTOUT size %d \n",  size);

    if (offset + sizeof(MixerFrameHdr) + size >= TX_RING_MMAP_SIZE)
        offset = 0;

    MixerFrame *frame = &tx[pending++ & TX_RING_RX_MASK];

    frame->data = &buffer[offset];
    MixerFrameHdr *hdr = (MixerFrameHdr *)frame->data;

    hdr->id             = id;
    hdr->sample_rate    = output_sample_rate;
    hdr->length         = size;

    memcpy(frame->data + sizeof(MixerFrameHdr), data, size);

    offset += sizeof(MixerFrameHdr) + size;

    done();
}



RxRing::RxRing()
    : offset(0), last_rx(0)

{
    buffer = (unsigned char *)mmap(NULL, RX_RING_MMAP_SIZE, PROT_READ | PROT_WRITE,
                                         MAP_ANONYMOUS | MAP_PRIVATE , -1, 0);
    if (buffer == MAP_FAILED)
        throw string("RxRing: mmap() call failed"); // throw std::bad_alloc();

    next_rx_frame = &rx[0];
    next_rx_frame->data = buffer;
}


RxRing::~RxRing()
{
    munmap(buffer, RX_RING_MMAP_SIZE);
}


// TODO: multiframe support must be added
inline void RxRing::prepare_next_frame(ssize_t last_length)
{
    offset += last_length;

    /** reserve space for at least UDP_MESSAGE_MAX in tail */
    if (RX_RING_MMAP_SIZE - offset < UDP_MESSAGE_MAX)
        offset = 0;

    /** prepare next ring buffer */
    next_rx_frame = &rx[++last_rx & RX_RING_RX_MASK];
    next_rx_frame->data = &buffer[offset];
}


void RxRing::handler(uint32_t ev, int fd)
{
    sockaddr_storage    saddr;
    socklen_t           recv_addr_len = sizeof(struct sockaddr_storage);
    ssize_t             length;
    int                 neighbor_id;


    do {

        length = ::recvfrom(fd, next_rx_frame->data, UDP_MESSAGE_MAX, 0,
                            reinterpret_cast<sockaddr *>(&saddr), &recv_addr_len);

        if (length < static_cast<ssize_t>(sizeof(MixerFrameHdr))) {
            if (errno != EAGAIN)
                ERROR("recvfrom(): %m");
            return;
        }

        if (!isNeighbor(saddr, neighbor_id))
            continue;

        MixerFrameHdr   *hdr = next_rx_frame->hdr;
        ssize_t         frame_length  = hdr->length + sizeof(MixerFrameHdr);

        if (length != frame_length) {
            ERROR("Unexpected pkt_length %ld (expected %ld) ", length, frame_length);
            continue;
        }

        struct backlog *bl = find_backlog_by_id(hdr->id);

        if (!bl)
            continue;

        do {
            bl_position_t last, next;

            last.pair = next.pair = bl->position.pair;
            ++next.end &= MIXER_BACKLOG_MASK;

            if (last.start == next.end) {
                DBG("Backlog overrun for %ld", hdr->id);
                break;
            }

            bl->frame[next.end].neighbor_id = neighbor_id;
            bl->frame[next.end].hdr         = hdr;

            if (__sync_bool_compare_and_swap(&bl->position.pair, last.pair, next.pair)) {
                prepare_next_frame(length);
                break;
            }

        } while (true);

    } while (true);
}

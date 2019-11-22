#include "AmLCContainers.h"

#include <utility>

#define USED_PORT2IDX(PORT) (PORT >> _BITOPS_LONG_SHIFT)

MEDIA_info::MEDIA_info(MEDIA_type type)
  : mtype(type),
    low_port(RTP_LOWPORT),
    high_port(RTP_HIGHPORT)
{
    memset(ports_state, 0, sizeof(ports_state));
}

MEDIA_info::~MEDIA_info()
{ }

void MEDIA_info::prepare()
{
    unsigned short ports_state_begin_it = USED_PORT2IDX(low_port);
    ports_state_begin_addr = &ports_state[ports_state_begin_it];

    unsigned short ports_state_end_it = USED_PORT2IDX(high_port) + !!(high_port%BITS_PER_LONG);
    ports_state_end_addr = &ports_state[ports_state_end_it];

    start_edge_bit_it =
        (ports_state_begin_it*BITS_PER_LONG > low_port) ?
            0 : low_port%BITS_PER_LONG;

    end_edge_bit_it =
        (ports_state_end_it*BITS_PER_LONG > high_port) ?
            high_port%BITS_PER_LONG + 1 : BITS_PER_LONG;

    //flag to determine RTCP ports to ignore in freeRtpPort
    rtp_bit_parity = start_edge_bit_it % 2;

    bzero(&ports_state,sizeof(ports_state));
    //set all bits for RTCP ports to make working optimization checks like if(~(*it))
    int mask = rtp_bit_parity ? 0x55 : 0xAA;
    memset(&ports_state[ports_state_begin_it], mask,
           (ports_state_end_addr - ports_state_begin_addr)*sizeof(unsigned long));

    ports_state_end_addr--;

    //set all leading bits before start_edge_bit_it in first bitmap element
    *ports_state_begin_addr |= (~(ULONG_MAX<<(start_edge_bit_it - 1)));
    //set all trailing bits after end_edge_bit_it in last bitmap element
    *ports_state_end_addr |= (~(ULONG_MAX>>(BITS_PER_LONG - end_edge_bit_it)));
}

unsigned short MEDIA_info::getNextRtpPort()
{
    unsigned short i = 0;
    unsigned long *it = ports_state_begin_addr;

    //process head
    if(~(*it)) {
        for(i = start_edge_bit_it; i < BITS_PER_LONG; i += 2) {
            if(!test_and_set_bit(i, it)) {
                goto bit_is_aquired;
            }
        }
    }

    //common cycle
    for(; it != ports_state_end_addr; it++) {
        if (!(~(*it))) // all bits set
            continue;
        for(i = 0; i < BITS_PER_LONG; i += 2) {
            if(!test_and_set_bit(i, it)) {
                goto bit_is_aquired;
            }
        }
    }

    //process tail
    if (~(*it)) {
        for(i = 0; i < end_edge_bit_it; i += 2) {
            if(!test_and_set_bit(i, it)) {
                goto bit_is_aquired;
            }
        }
    }

    //no free port found
    return 0;

  bit_is_aquired:
    return (static_cast<unsigned short>(it-ports_state) << _BITOPS_LONG_SHIFT)  + i;
}

void MEDIA_info::freeRtpPort(unsigned int port)
{
    if(port < low_port || port > high_port) {
        ERROR("error to free unexpected port: %u", port);
        return;
    }

    //ignore RTCP ports
    if(rtp_bit_parity ^ (port%2))
        return;

    clear_bit(port%BITS_PER_LONG, &ports_state[USED_PORT2IDX(port)]);
    __sync_synchronize();
}


void MEDIA_info::iterateUsedPorts(std::function<void(unsigned short, unsigned short)> cl)
{
    for(unsigned short port = low_port; port <= high_port; port+=2) {
        if(constant_test_bit(port%BITS_PER_LONG, &ports_state[USED_PORT2IDX(port)]) == true) {
            cl(port, port+1);
        }
    }
}

